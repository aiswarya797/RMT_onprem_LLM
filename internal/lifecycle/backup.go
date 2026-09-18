package lifecycle

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
	"rmt.local/monitor/internal/store"
)

type BackupResult struct {
	SchemaVersion        string                     `json:"schema_version"`
	Status               string                     `json:"status"`
	DeploymentID         string                     `json:"deployment_id"`
	DeploymentGeneration string                     `json:"deployment_generation"`
	RecoveryPointMS      int64                      `json:"recovery_point_ms"`
	ManifestSHA256       string                     `json:"manifest_sha256"`
	HighWater            store.BackupHighWaterMarks `json:"high_water"`
	BackupPath           string                     `json:"backup_path"`
	RecoveryKeyPath      string                     `json:"recovery_key_path,omitempty"`
	Published            bool                       `json:"published"`
}

func (m *Manager) CreateBackup(ctx context.Context, destination, keyPath, newKeyPath, deploymentID, generation string) (BackupResult, error) {
	var empty BackupResult
	lease, err := config.AcquireInstallationLease(m.Paths, false)
	if err != nil {
		return empty, err
	}
	defer lease.Close()
	if err := RequireRecoveryReady(m.Paths); err != nil {
		return empty, err
	}
	if !filepath.IsAbs(destination) || (keyPath == "") == (newKeyPath == "") || !validUUID(deploymentID) || !validUUID(generation) {
		return empty, errors.New("backup requires an absolute output, one recovery key file option, and reviewed deployment identity")
	}
	st, err := store.OpenExisting(m.Paths.Database, m.Clock)
	if err != nil {
		return empty, err
	}
	defer st.Close()
	state, err := st.DeploymentState(ctx)
	if err != nil {
		return empty, err
	}
	if state.DeploymentID != deploymentID || state.DeploymentGeneration != generation || !state.MutationsAllowed {
		return empty, store.ErrGenerationConflict
	}
	staging := filepath.Join(m.Paths.Support, "backup-staging")
	if err := config.EnsurePrivateDir(staging); err != nil {
		return empty, err
	}
	blobs := filepath.Join(m.Paths.Hub, "snapshots")
	if err := config.EnsurePrivateDir(blobs); err != nil {
		return empty, err
	}
	if err := backupSpacePreflight(m.Paths, filepath.Dir(destination), staging); err != nil {
		return empty, err
	}
	if newKeyPath != "" {
		if _, err := store.GenerateRecoveryKey(newKeyPath); err != nil {
			return empty, err
		}
		keyPath = newKeyPath
	}
	result, err := st.CreateConsistentBackup(ctx, store.BackupCreateOptions{
		DestinationPath: destination, RecoveryKeyPath: keyPath, StagingDirectory: staging,
		ConfirmDeploymentID: deploymentID, ExpectedGeneration: generation, CreatedMS: m.Clock.Now().UnixMilli(),
		AuxiliaryPaths: store.BackupAuxiliaryPaths{HubConfigPath: m.Paths.HubConfig, CollectorConfigPath: m.Paths.CollectorConfig, SessionSecretPath: m.Paths.SessionSecret, CAKeyPath: m.Paths.CAKey, CACertificatePath: m.Paths.CACert, HubKeyPath: m.Paths.HubKey, HubCertificatePath: m.Paths.HubCert, SnapshotBlobRoot: blobs, AttachmentBlobRoot: filepath.Join(m.Paths.Hub, "attachments"), NotificationSecretRoot: m.Paths.NotificationSecrets},
	})
	if err != nil && !result.Published {
		return empty, err
	}
	output := backupResult(result.Verification, destination)
	output.Published, output.RecoveryKeyPath = result.Published, newKeyPath
	output.Status = "created_verified"
	if err != nil {
		output.Status = "created_verified_status_update_failed"
	}
	return output, err
}

func (m *Manager) VerifyBackup(ctx context.Context, backupPath, keyPath, deploymentID string) (BackupResult, error) {
	staging := filepath.Join(m.Paths.Support, "backup-staging")
	if err := config.EnsurePrivateDir(staging); err != nil {
		return BackupResult{}, err
	}
	// Verification needs the operator's key and reviewed manifest owner, not the
	// current installation database or its trust material.
	result, err := store.VerifyBackup(ctx, store.BackupVerifyOptions{BackupPath: backupPath, RecoveryKeyPath: keyPath, StagingDirectory: staging, ConfirmDeploymentID: deploymentID})
	if err != nil {
		return BackupResult{}, err
	}
	output := backupResult(result, backupPath)
	output.Status = "verified"
	return output, nil
}

func backupResult(verified store.BackupVerification, path string) BackupResult {
	return BackupResult{SchemaVersion: domain.SchemaVersion, DeploymentID: verified.Manifest.DeploymentID, DeploymentGeneration: verified.Manifest.DeploymentGeneration, RecoveryPointMS: verified.Manifest.RecoveryPointMS, ManifestSHA256: verified.ManifestSHA256, HighWater: verified.Manifest.HighWater, BackupPath: path}
}

func backupSpacePreflight(paths config.Paths, destination, staging string) error {
	var input int64
	for _, path := range []string{paths.Database, paths.Database + "-wal", filepath.Join(paths.Hub, "snapshots")} {
		err := filepath.WalkDir(path, func(path string, entry os.DirEntry, walkErr error) error {
			if errors.Is(walkErr, os.ErrNotExist) {
				return nil
			}
			if walkErr != nil {
				return walkErr
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return errors.New("backup input contains a symlink")
			}
			if entry.IsDir() {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() || info.Size() < 0 || input > store.LiveDataLimitBytes-info.Size() {
				return errors.New("backup input exceeds live-data bound")
			}
			input += info.Size()
			return nil
		})
		if err != nil {
			return err
		}
	}
	// Snapshot, encrypted output and verification snapshot can coexist. Reserve
	// another 128 MiB for bounded concurrent collection and control writes.
	required := uint64(3*input + 128<<20)
	for _, path := range []string{destination, staging} {
		if err := config.RejectSymlinkTree(path); err != nil {
			return err
		}
		var stats syscall.Statfs_t
		if err := syscall.Statfs(path, &stats); err != nil {
			return err
		}
		if uint64(stats.Bavail)*uint64(stats.Bsize) < required {
			return errors.New("insufficient free space for a verified backup; existing files were preserved")
		}
	}
	return nil
}

func runBackupCLI(ctx context.Context, args []string, stdout, stderr io.Writer, manager *Manager, jsonOutput bool, fail func(int, string, string, string) int) int {
	if len(args) < 1 || (args[0] != "create" && args[0] != "verify") {
		return fail(2, "invalid_command", "Use: backup create --out FILE or backup verify --from FILE, with --key-file FILE and --confirm-deployment ID.", "fix_input")
	}
	fs := flag.NewFlagSet("backup "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "new encrypted backup file")
	from := fs.String("from", "", "encrypted backup to verify")
	keyFile := fs.String("key-file", "", "private recovery key file")
	keyOut := fs.String("key-out", "", "create a new private recovery key file")
	deployment := fs.String("confirm-deployment", "", "reviewed deployment ID")
	generation := fs.String("deployment-generation", "", "reviewed deployment generation")
	_ = fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		return fail(2, "invalid_input", "Invalid backup option.", "fix_input")
	}
	operationCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	var result BackupResult
	var err error
	if args[0] == "create" {
		if *from != "" {
			return fail(2, "invalid_input", "Create requires --out.", "fix_input")
		}
		result, err = manager.CreateBackup(operationCtx, *out, *keyFile, *keyOut, *deployment, *generation)
	} else {
		if *from == "" || *keyFile == "" || *keyOut != "" || *out != "" || *generation != "" {
			return fail(2, "invalid_input", "Verify requires --from, --key-file and --confirm-deployment.", "fix_input")
		}
		result, err = manager.VerifyBackup(operationCtx, *from, *keyFile, *deployment)
	}
	if err != nil && !result.Published {
		return fail(8, "backup_failed", "Backup operation failed. Existing backups and recovery keys are preserved.", "use_local_owner_command")
	}
	if jsonOutput {
		_ = protocol.WriteJSON(stdout, result)
	} else {
		fmt.Fprintf(stdout, "Backup %s: %s\nRecovery point: %d\n", result.Status, result.BackupPath, result.RecoveryPointMS)
		if result.RecoveryKeyPath != "" {
			fmt.Fprintf(stdout, "Recovery key: %s. Preserve it separately from the backup.\n", result.RecoveryKeyPath)
		}
	}
	if err != nil {
		return 8
	}
	return 0
}
