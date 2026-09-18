package lifecycle

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"rmt.local/monitor/internal/auth"
	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/enrollment"
	"rmt.local/monitor/internal/protocol"
	"rmt.local/monitor/internal/store"
)

type RestoreRequest struct {
	BackupPath, RecoveryKeyPath, ConfirmDeploymentID, ExpectedGeneration, ResumeTransaction string
	ConfirmRecoveryPointMS                                                                  int64
}

type RestoreResult struct {
	SchemaVersion        string                 `json:"schema_version"`
	Status               string                 `json:"status"`
	TransactionID        string                 `json:"transaction_id"`
	DeploymentID         string                 `json:"deployment_id"`
	DeploymentGeneration string                 `json:"deployment_generation"`
	RecoveryPointMS      int64                  `json:"recovery_point_ms"`
	DisplacedDirectory   string                 `json:"displaced_directory"`
	BootstrapTokenPath   string                 `json:"bootstrap_token_path"`
	ReenrollmentRequired bool                   `json:"reenrollment_required"`
	LaterChangesUnknown  bool                   `json:"later_changes_unknown"`
	RecoveryEvidence     store.RecoveryEvidence `json:"recovery_evidence"`
}

func (m *Manager) Restore(ctx context.Context, request RestoreRequest) (RestoreResult, error) {
	if request.ResumeTransaction != "" && (request.BackupPath != "" || request.RecoveryKeyPath != "") {
		return RestoreResult{}, errors.New("resume uses its prepared files; do not combine a transaction ID with a new backup or key")
	}
	if !validUUID(request.ConfirmDeploymentID) || !validUUID(request.ExpectedGeneration) || request.ConfirmRecoveryPointMS < 0 {
		return RestoreResult{}, errors.New("review the deployment, generation and recovery point before restore")
	}
	if err := config.EnsurePrivateDir(m.Paths.Support); err != nil {
		return RestoreResult{}, err
	}
	lease, err := config.AcquireInstallationLease(m.Paths, true)
	if err != nil {
		return RestoreResult{}, err
	}
	defer lease.Close()
	presence, err := m.serviceState(ctx, HubLabel)
	if err != nil || presence != ServicePresenceAbsent {
		return RestoreResult{}, errors.New("unload the hub LaunchAgent before offline restore; unknown service state is not stopped")
	}
	if _, err := ReadOwnerStatus(ctx, m.Paths.HubSocket); err == nil {
		return RestoreResult{}, errors.New("hub owner socket is still serving; stop the hub before restore")
	}
	journal, journalErr := readRecoveryJournal(m.Paths)
	if journalErr == nil && (journal.State == "prepared" || request.ResumeTransaction != "") {
		if request.ResumeTransaction != journal.TransactionID || request.ConfirmDeploymentID != journal.DeploymentID || request.ExpectedGeneration != journal.PreviousGeneration || request.ConfirmRecoveryPointMS != journal.RecoveryPointMS {
			return RestoreResult{}, errors.New("restore is already prepared; resume its exact recorded transaction and recovery point")
		}
		if journal.State == "committed" {
			return m.restoreResult(journal), nil
		}
		return m.activateRestore(ctx, journal)
	}
	if journalErr != nil && !errors.Is(journalErr, os.ErrNotExist) {
		return RestoreResult{}, journalErr
	}
	if request.ResumeTransaction != "" {
		return RestoreResult{}, errors.New("no prepared transaction matches the resume request")
	}
	if !filepath.IsAbs(request.BackupPath) || !filepath.IsAbs(request.RecoveryKeyPath) {
		return RestoreResult{}, errors.New("restore requires absolute backup and recovery key file paths")
	}
	if err := config.EnsurePrivateDir(recoveryDirectory(m.Paths)); err != nil {
		return RestoreResult{}, err
	}
	entries, err := os.ReadDir(recoveryDirectory(m.Paths))
	if err != nil {
		return RestoreResult{}, err
	}
	if len(entries) >= 33 {
		return RestoreResult{}, errors.New("recovery journal limit reached; archive reviewed prior recovery records before another restore")
	}
	// A readable current database must match the reviewed identity. Corrupt or
	// absent databases remain preserved; their later changes cannot be inferred.
	current, openErr := store.OpenReadOnly(m.Paths.Database, m.Clock)
	if openErr == nil {
		state, stateErr := current.DeploymentState(ctx)
		current.Close()
		if stateErr == nil && (state.DeploymentID != request.ConfirmDeploymentID || state.DeploymentGeneration != request.ExpectedGeneration) {
			return RestoreResult{}, store.ErrGenerationConflict
		}
	}
	transactionID, err := domain.NewUUID()
	if err != nil {
		return RestoreResult{}, err
	}
	transaction := filepath.Join(recoveryDirectory(m.Paths), transactionID)
	prepared := filepath.Join(transaction, "prepared")
	displaced := filepath.Join(transaction, "displaced")
	for _, directory := range []string{prepared, displaced} {
		if err := config.EnsurePrivateDir(directory); err != nil {
			return RestoreResult{}, err
		}
	}
	if err := backupSpacePreflight(m.Paths, transaction, transaction); err != nil {
		return RestoreResult{}, err
	}
	nextPaths := restorePreparedPaths(prepared)
	if _, err := ensureLocalCA(nextPaths, m.Clock.Now()); err != nil {
		return RestoreResult{}, err
	}
	ca, err := os.ReadFile(nextPaths.CACert)
	if err != nil {
		return RestoreResult{}, err
	}
	fingerprint, err := enrollment.FingerprintCertificatePEM(ca)
	if err != nil {
		return RestoreResult{}, err
	}
	generation, err := domain.NewUUID()
	if err != nil {
		return RestoreResult{}, err
	}
	// Preserve all fixed files before asking the store to reset restored trust.
	// Nothing below is installed live until the prepared journal is durable.
	names := restoreFilePaths(m.Paths)
	previous := make(map[string]string)
	for name, path := range names {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return RestoreResult{}, err
		}
		digest, err := copyRecoveryFile(ctx, path, filepath.Join(displaced, name), 0o400)
		if err != nil {
			return RestoreResult{}, err
		}
		previous[name] = digest
	}
	restored, err := store.RestoreBackup(ctx, store.RestoreOptions{BackupPath: request.BackupPath, RecoveryKeyPath: request.RecoveryKeyPath, OutputDatabasePath: nextPaths.Database, OutputDataDirectory: filepath.Join(prepared, "data"), ConfirmDeploymentID: request.ConfirmDeploymentID, ConfirmRecoveryPointMS: request.ConfirmRecoveryPointMS, NewDeploymentGeneration: generation, NewCAFingerprintSHA256: fingerprint, InstallingUserUID: os.Getuid(), NowMS: m.Clock.Now().UnixMilli(), HubStopped: true, DisplacedCopyPreserved: true})
	if err != nil {
		return RestoreResult{}, err
	}
	evidence := store.RecoveryEvidence{BackupHighWater: restored.Manifest.HighWater, KnownLaterRecords: []store.RecoveryInterval{}}
	if displacedStore, openErr := store.OpenReadOnly(m.Paths.Database, m.Clock); openErr == nil {
		observed, observationErr := displacedStore.ReadRecoveryEvidence(ctx, restored.Manifest)
		displacedStore.Close()
		if observationErr == nil {
			evidence = observed
		}
	}
	if err := writeJSONFile(filepath.Join(transaction, "verified-manifest.json"), restored.Manifest); err != nil {
		return RestoreResult{}, err
	}
	for _, name := range []string{"snapshots", "attachments", "notification-secrets"} {
		if err := config.EnsurePrivateDir(filepath.Join(prepared, "data", name)); err != nil {
			return RestoreResult{}, err
		}
	}
	// Restore configuration only through its closed schema. Installation paths
	// belong to this machine, and remote access remains disabled until reviewed.
	var saved savedHubConfig
	data, err := os.ReadFile(filepath.Join(restored.PreparedDataDirectory, "config", "hub.json"))
	if err != nil || protocol.DecodeStrictJSON(bytes.NewReader(data), 64<<10, &saved) != nil || saved.DeploymentID != request.ConfirmDeploymentID || saved.SchemaVersion != domain.SchemaVersion || saved.InferenceEnabled || validateListenAddress(saved.Listen) != nil {
		return RestoreResult{}, errors.New("backup hub configuration is invalid")
	}
	saved.Database, saved.OwnerSocket, saved.CollectorListen = m.Paths.Database, m.Paths.HubSocket, ""
	saved.CollectionEnabled = true
	if err := writeJSONFile(nextPaths.HubConfig, saved); err != nil {
		return RestoreResult{}, err
	}
	collector := map[string]any{"schema_version": domain.SchemaVersion, "deployment_id": request.ConfirmDeploymentID, "deployment_generation": generation, "owner_socket": m.Paths.CollectorSocket, "target_configured": false, "collection_enabled": false, "inference_enabled": false}
	if err := writeJSONFile(nextPaths.CollectorConfig, collector); err != nil {
		return RestoreResult{}, err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return RestoreResult{}, err
	}
	if err := config.WritePrivateFile(nextPaths.SessionSecret, secret); err != nil {
		return RestoreResult{}, err
	}
	preparedStore, err := store.OpenExisting(nextPaths.Database, m.Clock)
	if err != nil {
		return RestoreResult{}, err
	}
	service, err := auth.NewService(preparedStore, nextPaths, m.Clock)
	if err == nil {
		_, _, _, err = service.RenewBootstrap(ctx)
	}
	closeErr := preparedStore.Close()
	if err != nil {
		return RestoreResult{}, err
	}
	if closeErr != nil {
		return RestoreResult{}, closeErr
	}
	journal = recoveryJournal{SchemaVersion: domain.SchemaVersion, TransactionID: transactionID, DeploymentID: request.ConfirmDeploymentID, PreviousGeneration: request.ExpectedGeneration, DeploymentGeneration: generation, RecoveryPointMS: restored.Manifest.RecoveryPointMS, StartedMS: m.Clock.Now().UnixMilli(), State: "prepared", ManifestSHA256: restored.ManifestSHA256, Files: []recoveryFile{}, LaterChangesUnknown: true, RecoveryEvidence: evidence}
	for name := range names {
		path := filepath.Join(prepared, name)
		digest := ""
		if _, err := os.Lstat(path); err == nil {
			digest, err = recoveryFileHash(path)
			if err != nil {
				return RestoreResult{}, err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return RestoreResult{}, err
		}
		if digest == "" && previous[name] == "" {
			continue
		}
		journal.Files = append(journal.Files, recoveryFile{Name: name, SHA256: digest, PreviousSHA256: previous[name]})
	}
	if err := writeRecoveryJournal(m.Paths, journal); err != nil {
		return RestoreResult{}, err
	}
	if m.restorePrepared != nil {
		m.restorePrepared()
	}
	return m.activateRestore(ctx, journal)
}

func restorePreparedPaths(directory string) config.Paths {
	return config.Paths{Support: directory, Database: filepath.Join(directory, "monitor.sqlite3"), HubConfig: filepath.Join(directory, "hub.json"), CollectorConfig: filepath.Join(directory, "collector.json"), SessionSecret: filepath.Join(directory, "session.key"), BootstrapToken: filepath.Join(directory, "bootstrap.token"), CAKey: filepath.Join(directory, "ca.key"), CACert: filepath.Join(directory, "ca.pem"), HubKey: filepath.Join(directory, "hub.key"), HubCert: filepath.Join(directory, "hub.pem")}
}
func restoreFilePaths(paths config.Paths) map[string]string {
	return map[string]string{"monitor.sqlite3": paths.Database, "monitor.sqlite3-wal": paths.Database + "-wal", "monitor.sqlite3-shm": paths.Database + "-shm", "hub.json": paths.HubConfig, "collector.json": paths.CollectorConfig, "session.key": paths.SessionSecret, "bootstrap.token": paths.BootstrapToken, "ca.key": paths.CAKey, "ca.pem": paths.CACert, "hub.key": paths.HubKey, "hub.pem": paths.HubCert}
}
func (m *Manager) activateRestore(ctx context.Context, journal recoveryJournal) (RestoreResult, error) {
	if err := ctx.Err(); err != nil {
		return RestoreResult{}, err
	}
	transaction := filepath.Join(recoveryDirectory(m.Paths), journal.TransactionID)
	prepared := filepath.Join(transaction, "prepared")
	livePaths := restoreFilePaths(m.Paths)
	var required uint64 = 128 << 20
	for _, file := range journal.Files {
		if file.SHA256 != "" {
			info, err := os.Stat(filepath.Join(prepared, file.Name))
			if err != nil {
				return RestoreResult{}, err
			}
			required += uint64(info.Size())
		}
	}
	var volume syscall.Statfs_t
	if err := syscall.Statfs(m.Paths.Support, &volume); err != nil {
		return RestoreResult{}, err
	}
	if uint64(volume.Bavail)*uint64(volume.Bsize) < required {
		return RestoreResult{}, errors.New("restore remains prepared: insufficient space for atomic installation")
	}
	for _, file := range journal.Files {
		destination, ok := livePaths[file.Name]
		if !ok {
			return RestoreResult{}, errors.New("recovery journal names an unsupported file")
		}
		currentHash, err := recoveryFileHash(destination)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return RestoreResult{}, err
		}
		if file.SHA256 != "" && currentHash == file.SHA256 {
			continue
		}
		if currentHash != "" && currentHash != file.PreviousSHA256 {
			return RestoreResult{}, errors.New("live file changed after restore preparation; recovery remains blocked")
		}
		if file.SHA256 == "" {
			if currentHash != "" {
				if err := os.Remove(destination); err != nil {
					return RestoreResult{}, err
				}
			}
			continue
		}
		source := filepath.Join(prepared, file.Name)
		hash, err := recoveryFileHash(source)
		if err != nil || hash != file.SHA256 {
			return RestoreResult{}, errors.New("prepared recovery file failed verification")
		}
		if err := config.EnsurePrivateDir(filepath.Dir(destination)); err != nil {
			return RestoreResult{}, err
		}
		temporary := filepath.Join(filepath.Dir(destination), ".restore-"+journal.TransactionID+"-"+file.Name)
		if _, err := os.Lstat(temporary); err == nil {
			if err := config.ValidatePrivateFile(temporary); err != nil {
				return RestoreResult{}, err
			}
			// The verified immutable prepared source remains the surviving copy.
			if err := os.Remove(temporary); err != nil {
				return RestoreResult{}, err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return RestoreResult{}, err
		}
		if _, err := copyRecoveryFile(ctx, source, temporary, 0o600); err != nil {
			return RestoreResult{}, err
		}
		if err := os.Rename(temporary, destination); err != nil {
			return RestoreResult{}, err
		}
		if err := syncRecoveryDirectory(filepath.Dir(destination)); err != nil {
			return RestoreResult{}, err
		}
	}
	if err := installRecoveryBlobs(m.Paths, transaction, journal.ManifestSHA256); err != nil {
		return RestoreResult{}, err
	}

	if err := syncRecoveryDirectory(m.Paths.Hub); err != nil {
		return RestoreResult{}, err
	}
	now := m.Clock.Now().UnixMilli()
	journal.State, journal.CompletedMS = "committed", &now
	if err := writeJSONFile(filepath.Join(transaction, "summary.json"), journal); err != nil {
		return RestoreResult{}, err
	}
	if err := writeRecoveryJournal(m.Paths, journal); err != nil {
		return RestoreResult{}, err
	}
	return m.restoreResult(journal), nil
}

func recoveryFileHash(path string) (string, error) {
	if err := config.ValidatePrivateFile(path); err != nil {
		return "", err
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, store.LiveDataLimitBytes+1))
	if err != nil || n > store.LiveDataLimitBytes {
		return "", errors.New("recovery file exceeds bound")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
func copyRecoveryFile(ctx context.Context, source, destination string, mode os.FileMode) (string, error) {
	if err := config.ValidatePrivateFile(source); err != nil {
		return "", err
	}
	if err := config.EnsurePrivateDir(filepath.Dir(destination)); err != nil {
		return "", err
	}
	input, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	defer output.Close()
	hash := sha256.New()
	buffer := make([]byte, 64<<10)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n, readErr := input.Read(buffer)
		if n > 0 {
			total += int64(n)
			if total > store.LiveDataLimitBytes {
				return "", errors.New("recovery file exceeds bound")
			}
			if _, err := output.Write(buffer[:n]); err != nil {
				return "", err
			}
			hash.Write(buffer[:n])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return "", readErr
		}
	}
	if err := output.Chmod(mode); err != nil {
		return "", err
	}
	if err := output.Sync(); err != nil {
		return "", err
	}
	if err := output.Close(); err != nil {
		return "", err
	}
	if err := syncRecoveryDirectory(filepath.Dir(destination)); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
func syncRecoveryDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func runRestoreCLI(ctx context.Context, args []string, stdout, stderr io.Writer, manager *Manager, jsonOutput bool, fail func(int, string, string, string) int) int {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	fs.SetOutput(stderr)
	from := fs.String("from", "", "verified encrypted backup")
	key := fs.String("key-file", "", "private recovery key file")
	deployment := fs.String("confirm-deployment", "", "reviewed deployment ID")
	generation := fs.String("deployment-generation", "", "reviewed current generation")
	point := fs.Int64("confirm-recovery-point-ms", -1, "reviewed recovery point")
	resume := fs.String("resume-transaction", "", "resume a prepared recovery transaction")
	_ = fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return fail(2, "invalid_input", "Invalid restore option.", "fix_input")
	}
	operationCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	result, err := manager.Restore(operationCtx, RestoreRequest{BackupPath: *from, RecoveryKeyPath: *key, ConfirmDeploymentID: *deployment, ExpectedGeneration: *generation, ConfirmRecoveryPointMS: *point, ResumeTransaction: *resume})
	if err != nil {
		return fail(8, "restore_failed", "Restore did not complete. Run recovery inspect with the same installation-root and runtime-dir options for the verified transaction and exact resume arguments. Preserved files remain available.", "use_local_owner_command")
	}
	if jsonOutput {
		_ = json.NewEncoder(stdout).Encode(result)
	} else {
		fmt.Fprintf(stdout, "Restored to %d. Create a new administrator using %s, then explicitly re-enroll reviewed hosts.\nDisplaced files: %s. Later changes may be missing.\n", result.RecoveryPointMS, result.BootstrapTokenPath, result.DisplacedDirectory)
	}
	return 0
}

func (m *Manager) restoreResult(journal recoveryJournal) RestoreResult {
	transaction := filepath.Join(recoveryDirectory(m.Paths), journal.TransactionID)
	return RestoreResult{SchemaVersion: domain.SchemaVersion, Status: "restore_requires_bootstrap", TransactionID: journal.TransactionID, DeploymentID: journal.DeploymentID, DeploymentGeneration: journal.DeploymentGeneration, RecoveryPointMS: journal.RecoveryPointMS, DisplacedDirectory: filepath.Join(transaction, "displaced"), BootstrapTokenPath: m.Paths.BootstrapToken, ReenrollmentRequired: true, LaterChangesUnknown: true, RecoveryEvidence: journal.RecoveryEvidence}
}

func installRecoveryBlobs(paths config.Paths, transaction, manifestHash string) error {
	manifestPath := filepath.Join(transaction, "verified-manifest.json")
	if err := config.ValidatePrivateFile(manifestPath); err != nil {
		return err
	}
	data, err := os.ReadFile(manifestPath)
	if err != nil || len(data) > store.BackupManifestLimitBytes {
		return errors.New("recovery manifest is invalid")
	}
	var manifest store.BackupManifest
	if err := protocol.DecodeStrictJSON(bytes.NewReader(data), store.BackupManifestLimitBytes, &manifest); err != nil {
		return err
	}
	canonical, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(canonical)
	if hex.EncodeToString(digest[:]) != manifestHash {
		return errors.New("recovery manifest does not match the prepared transaction")
	}
	for _, name := range []string{"snapshots", "attachments", "notification-secrets"} {
		source := filepath.Join(transaction, "prepared", "data", name)
		destination := filepath.Join(paths.Hub, name)
		displaced := filepath.Join(transaction, "displaced", name)
		if _, err := os.Lstat(source); errors.Is(err, os.ErrNotExist) {
			if err := verifyRecoveryBlobs(destination, name, manifest); err != nil {
				return err
			}
			continue
		} else if err != nil {
			return err
		}
		if err := verifyRecoveryBlobs(source, name, manifest); err != nil {
			return err
		}
		if _, err := os.Lstat(destination); err == nil {
			if err := config.RejectSymlinkTree(destination); err != nil {
				return err
			}
			if _, err := os.Lstat(displaced); !errors.Is(err, os.ErrNotExist) {
				return errors.New("displaced blob directory already exists; inspect recovery")
			}
			if err := os.Rename(destination, displaced); err != nil {
				return err
			}
			if err := syncRecoveryDirectory(filepath.Dir(displaced)); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.Rename(source, destination); err != nil {
			return err
		}
		if err := syncRecoveryDirectory(paths.Hub); err != nil {
			return err
		}
		if err := syncRecoveryDirectory(filepath.Dir(source)); err != nil {
			return err
		}
	}
	return nil
}
func verifyRecoveryBlobs(root, name string, manifest store.BackupManifest) error {
	if err := config.RejectSymlinkTree(root); err != nil {
		return err
	}
	expected := make(map[string]string)
	for _, entry := range manifest.Files {
		if strings.HasPrefix(entry.Name, name+"/") {
			expected[strings.TrimPrefix(entry.Name, name+"/")] = entry.SHA256
		}
	}
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) && len(expected) == 0 {
		return nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	seen := 0
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		hash, ok := expected[filepath.ToSlash(relative)]
		if !ok {
			return errors.New("unexpected restored blob")
		}
		actual, err := recoveryFileHash(path)
		if err != nil || actual != hash {
			return errors.New("restored blob failed verification")
		}
		seen++
		return nil
	})
	if err != nil {
		return err
	}
	if seen != len(expected) {
		return errors.New("restored blob is missing")
	}
	return nil
}
