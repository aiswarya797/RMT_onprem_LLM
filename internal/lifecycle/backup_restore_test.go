package lifecycle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"rmt.local/monitor/internal/auth"
	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/store"
)

func TestLocalBackupRestorePreservesDisplacedStateAndResetsTrust(t *testing.T) {
	ctx := context.Background()
	paths := testPaths(t)
	manager := NewManager(paths, newFakeRunner(), fixedClock{time.Unix(1_800_000_000, 0)})
	setup, err := manager.SetupLocal(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	oldCA, _ := os.ReadFile(paths.CACert)
	oldSession, _ := os.ReadFile(paths.SessionSecret)
	oldDatabase, _ := os.ReadFile(paths.Database)
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(directory, "monitor.age")
	key := filepath.Join(filepath.Dir(out), "recovery.key")
	backup, err := manager.CreateBackup(ctx, out, "", key, setup.DeploymentID, setup.DeploymentGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if !backup.Published || backup.Status != "created_verified" {
		t.Fatalf("backup=%+v", backup)
	}
	verified, err := manager.VerifyBackup(ctx, out, key, setup.DeploymentID)
	if err != nil || verified.ManifestSHA256 != backup.ManifestSHA256 {
		t.Fatalf("verify=%+v err=%v", verified, err)
	}
	if _, err := manager.CreateBackup(ctx, out, key, "", setup.DeploymentID, setup.DeploymentGeneration); err == nil {
		t.Fatal("overwrote existing backup")
	}
	// A later administrative change is outside the backup and must appear in
	// the finite loss evidence instead of being reported as zero loss.
	beforeRestore, err := store.OpenExisting(paths.Database, manager.Clock)
	if err != nil {
		t.Fatal(err)
	}
	originalAuth, err := auth.NewService(beforeRestore, paths, manager.Clock)
	if err != nil {
		t.Fatal(err)
	}
	originalToken, err := os.ReadFile(paths.BootstrapToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := originalAuth.CreateFirstAdmin(ctx, string(originalToken), "later-owner", "later-owner-password-123", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := beforeRestore.Close(); err != nil {
		t.Fatal(err)
	}
	lease, err := config.AcquireInstallationLease(paths, false)
	if err != nil {
		t.Fatal(err)
	}
	request := RestoreRequest{BackupPath: out, RecoveryKeyPath: key, ConfirmDeploymentID: setup.DeploymentID, ExpectedGeneration: setup.DeploymentGeneration, ConfirmRecoveryPointMS: backup.RecoveryPointMS}
	if _, err := manager.Restore(ctx, request); err == nil {
		t.Fatal("restore admitted while hub lease held")
	}
	lease.Close()
	result, err := manager.Restore(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if result.DeploymentGeneration == setup.DeploymentGeneration || !result.ReenrollmentRequired || !result.LaterChangesUnknown {
		t.Fatalf("restore=%+v", result)
	}
	if !result.RecoveryEvidence.CurrentStateReadable || !result.RecoveryEvidence.SameGeneration || result.RecoveryEvidence.DisplacedHighWater == nil {
		t.Fatalf("missing displaced evidence: %+v", result.RecoveryEvidence)
	}
	foundLaterAudit := false
	for _, interval := range result.RecoveryEvidence.KnownLaterRecords {
		if interval.Class == "audit" && interval.RetainedRows > 0 && interval.FirstHubTimeMS != nil && interval.LastHubTimeMS != nil {
			foundLaterAudit = true
		}
	}
	if !foundLaterAudit {
		t.Fatal("later administrator change was omitted from recovery evidence")
	}
	newCA, _ := os.ReadFile(paths.CACert)
	newSession, _ := os.ReadFile(paths.SessionSecret)
	if bytes.Equal(oldCA, newCA) || bytes.Equal(oldSession, newSession) {
		t.Fatal("restored old trust material")
	}
	previous, err := os.ReadFile(filepath.Join(result.DisplacedDirectory, "monitor.sqlite3"))
	if err != nil || len(previous) == 0 || len(oldDatabase) == 0 {
		t.Fatal("displaced database missing")
	}
	info, err := os.Stat(filepath.Join(result.DisplacedDirectory, "ca.key"))
	if err != nil || info.Mode().Perm() != 0o400 {
		t.Fatal("displaced trust material is not readonly")
	}
	st, err := store.OpenExisting(paths.Database, manager.Clock)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	state, err := st.DeploymentState(ctx)
	if err != nil || state.RecoveryState != "restore_requires_bootstrap" || state.MutationsAllowed || state.RecoveryPointMS == nil || *state.RecoveryPointMS != backup.RecoveryPointMS {
		t.Fatalf("state=%+v err=%v", state, err)
	}
	service, err := auth.NewService(st, paths, manager.Clock)
	if err != nil {
		t.Fatal(err)
	}
	token, err := os.ReadFile(result.BootstrapTokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.CreateFirstAdmin(ctx, string(token), "restored-owner", "new-local-admin-password-123", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	state, err = st.DeploymentState(ctx)
	if err != nil || !state.MutationsAllowed {
		t.Fatalf("bootstrap state=%+v err=%v", state, err)
	}
	if err := RequireRecoveryReady(paths); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreRefusesLoadedOrUnknownHubAndWrongRecoveryPoint(t *testing.T) {
	ctx := context.Background()
	paths := testPaths(t)
	runner := newFakeRunner()
	manager := NewManager(paths, runner, fixedClock{time.Unix(1_800_000_000, 0)})
	setup, err := manager.SetupLocal(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	request := RestoreRequest{BackupPath: "/not-used", RecoveryKeyPath: "/not-used", ConfirmDeploymentID: setup.DeploymentID, ExpectedGeneration: setup.DeploymentGeneration, ConfirmRecoveryPointMS: 0}
	runner.loaded[HubLabel] = true
	if _, err := manager.Restore(ctx, request); err == nil {
		t.Fatal("loaded hub accepted")
	}
	delete(runner.loaded, HubLabel)
	runner.unknown[HubLabel] = true
	if _, err := manager.Restore(ctx, request); err == nil {
		t.Fatal("unknown hub state accepted")
	}
	before, _ := os.ReadFile(paths.CACert)
	delete(runner.unknown, HubLabel)
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(directory, "monitor.age")
	key := filepath.Join(filepath.Dir(out), "recovery.key")
	backup, err := manager.CreateBackup(ctx, out, "", key, setup.DeploymentID, setup.DeploymentGeneration)
	if err != nil {
		t.Fatal(err)
	}
	request.BackupPath, request.RecoveryKeyPath = out, key
	request.ConfirmRecoveryPointMS = backup.RecoveryPointMS + 1
	if _, err := manager.Restore(ctx, request); err == nil {
		t.Fatal("wrong recovery point accepted")
	}
	after, _ := os.ReadFile(paths.CACert)
	if !bytes.Equal(before, after) {
		t.Fatal("failed restore replaced live trust")
	}
	if err := RequireRecoveryReady(paths); err != nil {
		t.Fatal("preparation failure blocked unchanged live state", err)
	}
}

func TestInterruptedRestoreStaysBlockedUntilExactResume(t *testing.T) {
	ctx := context.Background()
	paths := testPaths(t)
	manager := NewManager(paths, newFakeRunner(), fixedClock{time.Unix(1_800_000_000, 0)})
	setup, err := manager.SetupLocal(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	out, key := filepath.Join(directory, "monitor.age"), filepath.Join(directory, "recovery.key")
	backup, err := manager.CreateBackup(ctx, out, "", key, setup.DeploymentID, setup.DeploymentGeneration)
	if err != nil {
		t.Fatal(err)
	}
	interrupted, cancel := context.WithCancel(ctx)
	manager.restorePrepared = cancel
	request := RestoreRequest{BackupPath: out, RecoveryKeyPath: key, ConfirmDeploymentID: setup.DeploymentID, ExpectedGeneration: setup.DeploymentGeneration, ConfirmRecoveryPointMS: backup.RecoveryPointMS}
	if _, err := manager.Restore(interrupted, request); err == nil {
		t.Fatal("cancelled activation succeeded")
	}
	manager.restorePrepared = nil
	if err := RequireRecoveryReady(paths); err == nil {
		t.Fatal("prepared recovery admitted startup")
	}
	journal, err := readRecoveryJournal(paths)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Restore(ctx, request); err == nil {
		t.Fatal("ambiguous retry created another restore")
	}
	request.ResumeTransaction = journal.TransactionID
	if _, err := manager.Restore(ctx, request); err == nil {
		t.Fatal("resume accepted fresh backup/key inputs")
	}
	if err := RequireRecoveryReady(paths); err == nil {
		t.Fatal("invalid mixed restore request activated prepared state")
	}
	request.BackupPath, request.RecoveryKeyPath = "", ""
	var output, errorsOutput bytes.Buffer
	if code := RunCLI(ctx, []string{"recovery", "inspect", "--json"}, &output, &errorsOutput, manager); code != 0 {
		t.Fatalf("prepared inspection unavailable: %d %s", code, output.String())
	}
	var inspection RecoveryInspection
	if err := json.Unmarshal(output.Bytes(), &inspection); err != nil || inspection.State != "prepared" || inspection.TransactionID != journal.TransactionID || inspection.RecoveryPointMS == nil || *inspection.RecoveryPointMS != backup.RecoveryPointMS {
		t.Fatalf("inspection lost recovery boundary: %+v %v", inspection, err)
	}
	resumeArgs, options, err := config.ExtractRuntimeOptions(inspection.ResumeArgv[1:])
	if err != nil || options.InstallationRoot != paths.Home || options.RuntimeDir != paths.Run {
		t.Fatalf("resume lost selected installation: %+v %v", options, err)
	}
	output.Reset()
	if code := RunCLI(ctx, append(resumeArgs, "--json"), &output, &errorsOutput, manager); code != 0 {
		t.Fatalf("discovered resume failed: %d %s", code, output.String())
	}
	var result RestoreResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	again, err := manager.Restore(ctx, request)
	if err != nil || again.DeploymentGeneration != result.DeploymentGeneration {
		t.Fatalf("committed resume changed generation: %+v %v", again, err)
	}
	st, err := store.OpenReadOnly(paths.Database, manager.Clock)
	if err != nil {
		t.Fatal(err)
	}
	state, err := st.DeploymentState(ctx)
	st.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRecoveryDeployment(paths, state); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(recoveryDirectory(paths), "active.json"), filepath.Join(recoveryDirectory(paths), "missing-for-test.json")); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRecoveryDeployment(paths, state); err == nil {
		t.Fatal("lost journal admitted restored database")
	}
}

func TestRestoreAcceptsVerifiedManifestLargerThanMutationBodyLimit(t *testing.T) {
	paths := testPaths(t)
	transaction := filepath.Join(paths.Support, "recovery", "large-manifest")
	for _, directory := range []string{paths.Hub, filepath.Join(transaction, "displaced"), filepath.Join(transaction, "prepared", "data", "snapshots"), filepath.Join(transaction, "prepared", "data", "attachments")} {
		if err := config.EnsurePrivateDir(directory); err != nil {
			t.Fatal(err)
		}
	}
	digest := sha256.Sum256(nil)
	manifest := store.BackupManifest{FormatVersion: "1.0", Files: []store.BackupManifestEntry{}}
	for index := 0; index < 500; index++ {
		name := fmt.Sprintf("%04d-empty-snapshot.bin", index)
		manifest.Files = append(manifest.Files, store.BackupManifestEntry{Name: "snapshots/" + name, Kind: "snapshot_blob", SHA256: hex.EncodeToString(digest[:])})
		if err := config.WritePrivateFile(filepath.Join(transaction, "prepared", "data", "snapshots", name), nil); err != nil {
			t.Fatal(err)
		}
	}
	encoded, err := json.Marshal(manifest)
	if err != nil || len(encoded) <= 64<<10 || len(encoded) > store.BackupManifestLimitBytes {
		t.Fatalf("invalid boundary fixture: %d %v", len(encoded), err)
	}
	if err := config.WritePrivateFile(filepath.Join(transaction, "verified-manifest.json"), encoded); err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256(encoded)
	if err := installRecoveryBlobs(paths, transaction, hex.EncodeToString(expected[:])); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(paths.Hub, "snapshots"))
	if err != nil || len(entries) != 500 {
		t.Fatalf("restored blobs: %d %v", len(entries), err)
	}
}
