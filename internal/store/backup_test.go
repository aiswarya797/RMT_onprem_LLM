package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"rmt.local/monitor/internal/domain"
)

type snapshotBoundaryClock struct {
	now     time.Time
	pinned  chan struct{}
	proceed chan struct{}
	once    sync.Once
}

func (c *snapshotBoundaryClock) Now() time.Time {
	c.once.Do(func() {
		close(c.pinned)
		<-c.proceed
	})
	return c.now
}

type backupFixture struct {
	store      *Store
	clock      *testClock
	state      domain.DeploymentState
	root       string
	staging    string
	recovery   string
	auxiliary  BackupAuxiliaryPaths
	createdMS  int64
	adminCount int
}

func newBackupFixture(t *testing.T) backupFixture {
	t.Helper()
	root := t.TempDir()
	clock := &testClock{now: time.UnixMilli(1_800_000_000_000)}
	store, err := Open(filepath.Join(root, "monitor.sqlite3"), clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	state, _, err := store.EnsureDeployment(context.Background(), "backup-test")
	if err != nil {
		t.Fatal(err)
	}
	adminID := mustTestUUID(t)
	if _, err := store.db.Exec(`INSERT INTO users(id,deployment_id,name,argon2_hash,role,disabled,trust_generation,historical_restored,version,created_ms,updated_ms) VALUES(?,?,?,'00000000000000000000000000000000','admin',0,?,0,1,?,?)`, adminID, state.DeploymentID, "original-admin", state.DeploymentGeneration, clock.Now().UnixMilli(), clock.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(root, "staging")
	blobs := filepath.Join(root, "blobs")
	attachments := filepath.Join(root, "attachments")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(blobs, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(attachments, 0o700); err != nil {
		t.Fatal(err)
	}
	paths := BackupAuxiliaryPaths{
		HubConfigPath:       writePrivateTestFile(t, root, "hub.json", []byte(`{"listen":"127.0.0.1:9443"}`)),
		CollectorConfigPath: writePrivateTestFile(t, root, "collector.json", []byte(`{"mode":"local"}`)),
		SessionSecretPath:   writePrivateTestFile(t, root, "session.key", []byte("session-secret")),
		CAKeyPath:           writePrivateTestFile(t, root, "ca.key", []byte("old-ca-key")),
		CACertificatePath:   writePrivateTestFile(t, root, "ca.pem", []byte("old-ca-certificate")),
		SnapshotBlobRoot:    blobs,
		AttachmentBlobRoot:  attachments,
	}
	emptyHash := sha256.Sum256(nil)
	snapshotID := mustTestUUID(t)
	if _, err := store.db.Exec(`INSERT INTO snapshots(id,deployment_id,type,schema_version,revision,query_json,effective_range_json,payload_hash,relative_blob_path,size_bytes,created_ms,expires_ms) VALUES(?,?,'recovery_report','1.0',1,'{}','{}',?,'empty.bin',0,?,?)`, snapshotID, state.DeploymentID, hex.EncodeToString(emptyHash[:]), clock.Now().UnixMilli(), clock.Now().Add(time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	writePrivateTestFile(t, blobs, "empty.bin", nil)
	attachment := []byte("operator-approved staged attachment")
	attachmentHash := sha256.Sum256(attachment)
	attachmentID := mustTestUUID(t)
	if _, err := store.db.Exec(`INSERT INTO attachments(id,deployment_id,actor_user_id,filename,media_type,relative_blob_path,size_bytes,sha256,verification_state,staged_ms,expires_ms) VALUES(?,?,?,'evidence.txt','text/plain','evidence.bin',?,?, 'operator_approved_unverified',?,?)`, attachmentID, state.DeploymentID, adminID, len(attachment), hex.EncodeToString(attachmentHash[:]), clock.Now().UnixMilli(), clock.Now().Add(time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	writePrivateTestFile(t, attachments, "evidence.bin", attachment)
	recovery := filepath.Join(root, "recovery key with spaces.txt")
	if _, err := GenerateRecoveryKey(recovery); err != nil {
		t.Fatal(err)
	}
	return backupFixture{store: store, clock: clock, state: state, root: root, staging: staging, recovery: recovery, auxiliary: paths, createdMS: clock.Now().UnixMilli(), adminCount: 1}
}

func TestBackupIncludesLeasedNotificationSecretReferences(t *testing.T) {
	fixture := newBackupFixture(t)
	ctx := context.Background()
	secretRoot := filepath.Join(fixture.root, "notification-secrets")
	if err := os.Mkdir(secretRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	refA, refB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	writePrivateTestFile(t, secretRoot, "key", make([]byte, 32))
	writePrivateTestFile(t, secretRoot, refA, []byte(strings.Repeat("a", 29)))
	writePrivateTestFile(t, secretRoot, refB, []byte(strings.Repeat("b", 29)))
	fixture.auxiliary.NotificationSecretRoot = secretRoot
	destinationID := mustTestUUID(t)
	if _, err := fixture.store.db.Exec(`INSERT INTO destinations(id,deployment_id,type,display_name,secret_ref,configuration_json,version,created_ms,updated_ms) VALUES(?,?, 'webhook','Backup receiver',?,'{}',1,?,?)`, destinationID, fixture.state.DeploymentID, refA, fixture.createdMS, fixture.createdMS); err != nil {
		t.Fatal(err)
	}
	deliveryID := mustTestUUID(t)
	leaseToken := mustTestUUID(t)
	if _, err := fixture.store.db.Exec(`INSERT INTO outbox(id,deployment_id,instance_id,transition_seq,destination_id,destination_revision,destination_secret_ref,rule_revision,incident_generation,idempotency_key,payload_json,state,attempts,lease_token,lease_until_ms,next_attempt_ms,last_error_code,accepted_unknown,expires_ms,created_ms) VALUES(?,?,NULL,NULL,?,?,?,NULL,1,?,'{}','leased',1,?,?,NULL,NULL,0,?,?)`, deliveryID, fixture.state.DeploymentID, destinationID, 1, refB, "backup-delivery-"+deliveryID, leaseToken, fixture.createdMS+30_000, fixture.createdMS+86_400_000, fixture.createdMS); err != nil {
		t.Fatal(err)
	}
	snapshotPath, _, err := fixture.store.createSQLiteSnapshot(ctx, fixture.staging)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(snapshotPath)
	inputs, _, _, err := prepareBackupInputs(ctx, snapshotPath, fixture.auxiliary)
	if err != nil {
		t.Fatal(err)
	}
	wanted := map[string]bool{"notification-secrets/key": false, "notification-secrets/" + refA: false, "notification-secrets/" + refB: false}
	for _, input := range inputs {
		if _, ok := wanted[input.entry.Name]; ok {
			wanted[input.entry.Name] = true
		}
	}
	for name, found := range wanted {
		if !found {
			t.Fatalf("backup input missing %s", name)
		}
	}
}

func TestEncryptedBackupVerifyAndTwoRestoreGenerations(t *testing.T) {
	fixture := newBackupFixture(t)
	ctx := context.Background()
	commandStartedMS := fixture.createdMS
	fixture.clock.now = time.UnixMilli(commandStartedMS + 1_000)
	auditID := mustTestUUID(t)
	if _, err := fixture.store.db.Exec(`INSERT INTO audit(id,deployment_id,actor_user_id,action,resource_id,time_ms,allowlisted_detail_json) VALUES(?,?,NULL,'backup.boundary.fixture',NULL,?,'{}')`, auditID, fixture.state.DeploymentID, fixture.clock.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	firstBackup := filepath.Join(fixture.root, "first monitor backup.age")
	first, err := fixture.store.CreateConsistentBackup(ctx, BackupCreateOptions{
		DestinationPath: firstBackup, RecoveryKeyPath: fixture.recovery, StagingDirectory: fixture.staging,
		AuxiliaryPaths: fixture.auxiliary, ConfirmDeploymentID: fixture.state.DeploymentID,
		ExpectedGeneration: fixture.state.DeploymentGeneration, CreatedMS: commandStartedMS,
	})
	firstRecoveryPointMS := fixture.clock.Now().UnixMilli()
	if err != nil || !first.Published || first.Verification.Manifest.Database.Bytes == 0 || len(first.Verification.Manifest.Files) != 7 || first.Verification.Manifest.RecoveryPointMS != firstRecoveryPointMS || first.Verification.Manifest.CreatedMS != firstRecoveryPointMS || first.Verification.Manifest.HighWater.AuditRowID == 0 {
		t.Fatalf("first backup = %#v, %v", first, err)
	}
	if verified, err := VerifyBackup(ctx, BackupVerifyOptions{BackupPath: firstBackup, RecoveryKeyPath: fixture.recovery, StagingDirectory: fixture.staging, ConfirmDeploymentID: fixture.state.DeploymentID}); err != nil || verified.ManifestSHA256 != first.Verification.ManifestSHA256 {
		t.Fatalf("verify = %#v, %v", verified, err)
	}

	firstRestored, firstStore := restoreFixtureBackup(t, fixture, firstBackup, firstRecoveryPointMS, 1)
	if firstRestored.ArchivedUsers != 1 || firstRestored.NewlyArchivedUsers != 1 {
		t.Fatalf("first archived users = %#v", firstRestored)
	}
	completeRestoredBootstrap(t, firstStore, fixture.clock, "restored-admin-1", 1, firstRecoveryPointMS)

	secondCreatedMS := firstRecoveryPointMS + 2_000
	fixture.clock.now = time.UnixMilli(secondCreatedMS)
	secondState, err := firstStore.DeploymentState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	secondBackup := filepath.Join(fixture.root, "second-monitor-backup.age")
	second, err := firstStore.CreateConsistentBackup(ctx, BackupCreateOptions{
		DestinationPath: secondBackup, RecoveryKeyPath: fixture.recovery, StagingDirectory: fixture.staging,
		AuxiliaryPaths: fixture.auxiliary, ConfirmDeploymentID: secondState.DeploymentID,
		ExpectedGeneration: secondState.DeploymentGeneration, CreatedMS: secondCreatedMS,
	})
	if err != nil || !second.Published {
		t.Fatalf("second backup = %#v, %v", second, err)
	}
	secondRestored, secondStore := restoreFixtureBackup(t, fixture, secondBackup, secondCreatedMS, 2)
	if secondRestored.ArchivedUsers != 2 || secondRestored.NewlyArchivedUsers != 1 {
		t.Fatalf("second archived users = %#v", secondRestored)
	}
	completeRestoredBootstrap(t, secondStore, fixture.clock, "restored-admin-2", 2, secondCreatedMS)
}

func TestBackupRejectsWrongKeyTruncationOverwriteAndUnsafeInputs(t *testing.T) {
	fixture := newBackupFixture(t)
	ctx := context.Background()
	backup := filepath.Join(fixture.root, "valid.age")
	if _, err := fixture.store.CreateConsistentBackup(ctx, BackupCreateOptions{DestinationPath: backup, RecoveryKeyPath: fixture.recovery, StagingDirectory: fixture.staging, AuxiliaryPaths: fixture.auxiliary, ConfirmDeploymentID: fixture.state.DeploymentID, ExpectedGeneration: fixture.state.DeploymentGeneration, CreatedMS: fixture.createdMS}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.CreateConsistentBackup(ctx, BackupCreateOptions{DestinationPath: backup, RecoveryKeyPath: fixture.recovery, StagingDirectory: fixture.staging, AuxiliaryPaths: fixture.auxiliary, ConfirmDeploymentID: fixture.state.DeploymentID, ExpectedGeneration: fixture.state.DeploymentGeneration, CreatedMS: fixture.createdMS}); err == nil {
		t.Fatal("backup overwrote an existing destination")
	}
	wrongKey := filepath.Join(fixture.root, "wrong.key")
	if _, err := GenerateRecoveryKey(wrongKey); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBackup(ctx, BackupVerifyOptions{BackupPath: backup, RecoveryKeyPath: wrongKey, StagingDirectory: fixture.staging, ConfirmDeploymentID: fixture.state.DeploymentID}); err == nil {
		t.Fatal("wrong recovery key verified backup")
	}
	contents, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	truncated := writePrivateTestFile(t, fixture.root, "truncated.age", contents[:len(contents)/2])
	if _, err := VerifyBackup(ctx, BackupVerifyOptions{BackupPath: truncated, RecoveryKeyPath: fixture.recovery, StagingDirectory: fixture.staging, ConfirmDeploymentID: fixture.state.DeploymentID}); err == nil {
		t.Fatal("truncated encrypted backup verified")
	}
	if _, err := GenerateRecoveryKey(fixture.recovery); err == nil {
		t.Fatal("recovery key creation overwrote existing key")
	}
	linked := filepath.Join(fixture.root, "linked-session.key")
	if err := os.Symlink(fixture.auxiliary.SessionSecretPath, linked); err != nil {
		t.Fatal(err)
	}
	unsafe := fixture.auxiliary
	unsafe.SessionSecretPath = linked
	if _, _, _, err := prepareBackupInputs(ctx, backup, unsafe); err == nil {
		t.Fatal("symlinked key package input was accepted")
	}
}

func TestSQLiteSnapshotPinsRecoveryPointAcrossConcurrentWriterAndMultipleSteps(t *testing.T) {
	fixture := newBackupFixture(t)
	ctx := context.Background()
	padding := strings.Repeat("x", 3000)
	transaction, err := fixture.store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 500; index++ {
		id := fmt.Sprintf("60000000-0000-4000-8000-%012d", index)
		detail := fmt.Sprintf(`{"padding":%q}`, padding)
		if _, err := transaction.ExecContext(ctx, `INSERT INTO audit(id,deployment_id,actor_user_id,action,resource_id,time_ms,allowlisted_detail_json) VALUES(?,?,NULL,'backup.multistep.fixture',NULL,?,?)`, id, fixture.state.DeploymentID, fixture.createdMS, detail); err != nil {
			transaction.Rollback()
			t.Fatal(err)
		}
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
	var pageCount, beforeHighWater int64
	if err := fixture.store.db.QueryRowContext(ctx, `PRAGMA page_count`).Scan(&pageCount); err != nil {
		t.Fatal(err)
	}
	if pageCount <= 256 {
		t.Fatalf("fixture has %d pages; online backup would not require multiple 256-page steps", pageCount)
	}
	if err := fixture.store.db.QueryRowContext(ctx, `SELECT max(rowid) FROM audit`).Scan(&beforeHighWater); err != nil {
		t.Fatal(err)
	}

	writer, err := OpenExisting(filepath.Join(fixture.root, "monitor.sqlite3"), fixture.clock)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	boundary := &snapshotBoundaryClock{now: time.UnixMilli(fixture.createdMS + 1_000), pinned: make(chan struct{}), proceed: make(chan struct{})}
	fixture.store.clock = boundary
	type backupOutcome struct {
		result BackupCreateResult
		err    error
	}
	outcome := make(chan backupOutcome, 1)
	backupPath := filepath.Join(fixture.root, "concurrent-writer.age")
	go func() {
		result, err := fixture.store.CreateConsistentBackup(ctx, BackupCreateOptions{
			DestinationPath: backupPath, RecoveryKeyPath: fixture.recovery, StagingDirectory: fixture.staging,
			AuxiliaryPaths: fixture.auxiliary, ConfirmDeploymentID: fixture.state.DeploymentID,
			ExpectedGeneration: fixture.state.DeploymentGeneration, CreatedMS: fixture.createdMS,
		})
		outcome <- backupOutcome{result: result, err: err}
	}()
	select {
	case <-boundary.pinned:
	case <-time.After(2 * time.Second):
		close(boundary.proceed)
		select {
		case <-outcome:
		case <-time.After(2 * time.Second):
		}
		t.Fatal("backup did not establish its source snapshot")
	}
	lateID := "70000000-0000-4000-8000-000000000001"
	_, writeErr := writer.db.ExecContext(ctx, `INSERT INTO audit(id,deployment_id,actor_user_id,action,resource_id,time_ms,allowlisted_detail_json) VALUES(?,?,NULL,'backup.concurrent.fixture',NULL,?,'{}')`, lateID, fixture.state.DeploymentID, boundary.now.Add(time.Second).UnixMilli())
	close(boundary.proceed)
	var created backupOutcome
	select {
	case created = <-outcome:
	case <-time.After(10 * time.Second):
		t.Fatal("multi-step backup did not finish after releasing its pinned boundary")
	}
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	if created.err != nil {
		t.Fatal(created.err)
	}
	manifest := created.result.Verification.Manifest
	if manifest.RecoveryPointMS != boundary.now.UnixMilli() || manifest.HighWater.AuditRowID != beforeHighWater {
		t.Fatalf("snapshot boundary drifted: recovery=%d audit_high_water=%d, want recovery=%d audit_high_water=%d", manifest.RecoveryPointMS, manifest.HighWater.AuditRowID, boundary.now.UnixMilli(), beforeHighWater)
	}
	var currentHighWater int64
	if err := writer.db.QueryRowContext(ctx, `SELECT max(rowid) FROM audit`).Scan(&currentHighWater); err != nil {
		t.Fatal(err)
	}
	if currentHighWater <= manifest.HighWater.AuditRowID {
		t.Fatalf("concurrent writer was not committed after pinned snapshot: current=%d snapshot=%d", currentHighWater, manifest.HighWater.AuditRowID)
	}
}

func restoreFixtureBackup(t *testing.T, fixture backupFixture, backup string, recoveryPointMS int64, generationNumber int) (RestorePreparation, *Store) {
	t.Helper()
	generation := mustTestUUID(t)
	outputRoot := filepath.Join(fixture.root, "restore-"+time.UnixMilli(recoveryPointMS).Format("150405.000")+"-"+string(rune('0'+generationNumber)))
	if err := os.Mkdir(outputRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(outputRoot, "prepared-data")
	databasePath := filepath.Join(outputRoot, "restored.sqlite3")
	result, err := RestoreBackup(context.Background(), RestoreOptions{
		BackupPath: backup, RecoveryKeyPath: fixture.recovery, OutputDatabasePath: databasePath, OutputDataDirectory: dataDir,
		ConfirmDeploymentID: fixture.state.DeploymentID, ConfirmRecoveryPointMS: recoveryPointMS,
		NewDeploymentGeneration: generation, NewCAFingerprintSHA256: hex.EncodeToString(make([]byte, sha256.Size)),
		InstallingUserUID: os.Getuid(), NowMS: recoveryPointMS + 1_000, HubStopped: true, DisplacedCopyPreserved: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "config", "hub.json")); err != nil {
		t.Fatalf("restored config: %v", err)
	}
	if info, err := os.Stat(filepath.Join(dataDir, "snapshots", "empty.bin")); err != nil || info.Size() != 0 {
		t.Fatalf("restored empty snapshot: %#v, %v", info, err)
	}
	if contents, err := os.ReadFile(filepath.Join(dataDir, "attachments", "evidence.bin")); err != nil || string(contents) != "operator-approved staged attachment" {
		t.Fatalf("restored attachment: %q, %v", contents, err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "keys", "ca.key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old trust key was restored: %v", err)
	}
	restoredStore, err := OpenExisting(databasePath, fixture.clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { restoredStore.Close() })
	state, err := restoredStore.DeploymentState(context.Background())
	if err != nil || state.RecoveryState != "restore_requires_bootstrap" || state.MutationsAllowed || state.RecoveryPointMS == nil || *state.RecoveryPointMS != recoveryPointMS {
		t.Fatalf("restored state = %#v, %v", state, err)
	}
	inventory, err := restoredStore.ReadQueryInventory(context.Background())
	if err != nil || inventory.Deployment.RecoveryPointMS == nil || *inventory.Deployment.RecoveryPointMS != recoveryPointMS {
		t.Fatalf("restored query state = %#v, %v", inventory.Deployment, err)
	}
	return result, restoredStore
}

func completeRestoredBootstrap(t *testing.T, store *Store, clock *testClock, username string, expectedHistorical int64, recoveryPointMS int64) {
	t.Helper()
	clock.now = time.UnixMilli(recoveryPointMS + 1_500)
	token := HashForTest("restore-token-" + username)
	if err := store.PutFirstAdminBootstrap(context.Background(), token, clock.Now().Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeBootstrapAndCreateAdmin(context.Background(), token, username, "00000000000000000000000000000000"); err != nil {
		t.Fatal(err)
	}
	state, err := store.DeploymentState(context.Background())
	if err != nil || state.RecoveryState != "normal" || !state.MutationsAllowed || state.RecoveryPointMS == nil || *state.RecoveryPointMS != recoveryPointMS {
		t.Fatalf("completed restore state = %#v, %v", state, err)
	}
	var transitionState string
	var archived int64
	if err := store.db.QueryRow(`SELECT state,archived_user_count FROM restore_bootstrap_transitions WHERE deployment_id=? AND deployment_generation=?`, state.DeploymentID, state.DeploymentGeneration).Scan(&transitionState, &archived); err != nil || transitionState != "bootstrap_complete" || archived != expectedHistorical {
		t.Fatalf("transition state=%q archived=%d err=%v", transitionState, archived, err)
	}
}

func writePrivateTestFile(t *testing.T, directory, name string, contents []byte) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustTestUUID(t *testing.T) string {
	t.Helper()
	value, err := domain.NewUUID()
	if err != nil {
		t.Fatal(err)
	}
	return value
}
