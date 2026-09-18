package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"time"

	"github.com/mattn/go-sqlite3"
)

type BackupCreateOptions struct {
	DestinationPath     string
	RecoveryKeyPath     string
	StagingDirectory    string
	AuxiliaryPaths      BackupAuxiliaryPaths
	ConfirmDeploymentID string
	ExpectedGeneration  string
	CreatedMS           int64
}

type BackupCreateResult struct {
	Verification BackupVerification
	Published    bool
}

type BackupVerifyOptions struct {
	BackupPath          string
	RecoveryKeyPath     string
	StagingDirectory    string
	ConfirmDeploymentID string
}

func (s *Store) CreateConsistentBackup(ctx context.Context, options BackupCreateOptions) (BackupCreateResult, error) {
	if !validUUIDText(options.ConfirmDeploymentID) || !validUUIDText(options.ExpectedGeneration) || options.CreatedMS < 0 {
		return BackupCreateResult{}, errors.New("invalid backup creation request")
	}
	if err := validatePrivateDirectory(options.StagingDirectory); err != nil {
		return BackupCreateResult{}, err
	}
	// Fresh installations may not have run their first maintenance tick. Seed
	// the reviewed maintenance row before the SQLite snapshot so the backup is
	// itself restorable and the final success marker has a durable home.
	if err := s.ensureBackupMaintenance(ctx, options.ConfirmDeploymentID, options.ExpectedGeneration, options.CreatedMS); err != nil {
		return BackupCreateResult{}, err
	}
	identity, recipientHash, err := loadRecoveryIdentity(options.RecoveryKeyPath)
	if err != nil {
		return BackupCreateResult{}, err
	}
	snapshotPath, recoveryPointMS, err := s.createSQLiteSnapshot(ctx, options.StagingDirectory)
	if err != nil {
		return BackupCreateResult{}, err
	}
	defer os.Remove(snapshotPath)
	createdMS := options.CreatedMS
	if createdMS < recoveryPointMS {
		createdMS = recoveryPointMS
	}
	manifest, err := inspectBackupSnapshot(ctx, snapshotPath, recipientHash, createdMS, recoveryPointMS)
	if err != nil {
		return BackupCreateResult{}, err
	}
	if manifest.DeploymentID != options.ConfirmDeploymentID || manifest.DeploymentGeneration != options.ExpectedGeneration {
		return BackupCreateResult{}, ErrGenerationConflict
	}
	inputs, keyPackageHash, auxiliaryBytes, err := prepareBackupInputs(ctx, snapshotPath, options.AuxiliaryPaths)
	if err != nil {
		return BackupCreateResult{}, err
	}
	if manifest.Database.Bytes > LiveDataLimitBytes-auxiliaryBytes {
		return BackupCreateResult{}, errors.New("backup input exceeds live-data bound")
	}
	manifest.KeyPackageSHA256 = keyPackageHash
	manifest.Files = make([]BackupManifestEntry, len(inputs))
	for index := range inputs {
		manifest.Files[index] = inputs[index].entry
	}
	if err := validateBackupManifest(manifest, recipientHash); err != nil {
		return BackupCreateResult{}, err
	}
	manifestHash, encryptedPath, err := writeEncryptedBackup(ctx, options.DestinationPath, snapshotPath, inputs, manifest, identity)
	if err != nil {
		return BackupCreateResult{}, err
	}
	defer os.Remove(encryptedPath)
	verification, err := VerifyBackup(ctx, BackupVerifyOptions{BackupPath: encryptedPath, RecoveryKeyPath: options.RecoveryKeyPath, StagingDirectory: options.StagingDirectory, ConfirmDeploymentID: options.ConfirmDeploymentID})
	if err != nil {
		return BackupCreateResult{}, err
	}
	if verification.ManifestSHA256 != manifestHash {
		return BackupCreateResult{}, errors.New("backup verification manifest mismatch")
	}
	if err := publishExclusive(encryptedPath, options.DestinationPath); err != nil {
		return BackupCreateResult{}, err
	}
	result := BackupCreateResult{Verification: verification, Published: true}
	if err := s.markBackupCompleted(ctx, options.ConfirmDeploymentID, options.ExpectedGeneration, manifest.CreatedMS); err != nil {
		return result, err
	}
	return result, nil
}

func VerifyBackup(ctx context.Context, options BackupVerifyOptions) (BackupVerification, error) {
	if !validUUIDText(options.ConfirmDeploymentID) {
		return BackupVerification{}, errors.New("invalid backup verification request")
	}
	verification, databasePath, err := decryptBackupToStaging(ctx, options.BackupPath, options.RecoveryKeyPath, options.StagingDirectory, "")
	if err != nil {
		return BackupVerification{}, err
	}
	defer os.Remove(databasePath)
	if verification.Manifest.DeploymentID != options.ConfirmDeploymentID {
		return BackupVerification{}, ErrOwnershipMismatch
	}
	if err := verifySQLiteSnapshot(ctx, databasePath, verification.Manifest); err != nil {
		return BackupVerification{}, err
	}
	return verification, nil
}

func (s *Store) createSQLiteSnapshot(ctx context.Context, stagingDirectory string) (string, int64, error) {
	temporary, err := os.CreateTemp(stagingDirectory, ".rmt-snapshot-*.sqlite3")
	if err != nil {
		return "", 0, err
	}
	snapshotPath := temporary.Name()
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		os.Remove(snapshotPath)
		return "", 0, err
	}
	if err := temporary.Close(); err != nil {
		os.Remove(snapshotPath)
		return "", 0, err
	}
	release, err := s.acquireWrite(ctx)
	if err != nil {
		os.Remove(snapshotPath)
		return "", 0, err
	}
	defer release()
	source, err := s.db.Conn(ctx)
	if err != nil {
		os.Remove(snapshotPath)
		return "", 0, err
	}
	defer source.Close()
	sourceSnapshot, err := source.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		os.Remove(snapshotPath)
		return "", 0, err
	}
	defer sourceSnapshot.Rollback()
	// BEGIN is deferred in SQLite. The first read pins the WAL end mark before
	// we record the receipt boundary or initialize the online backup. Holding
	// this transaction makes every backup step read that same database image,
	// including when another Store instance commits concurrently.
	var pinnedGeneration string
	if err := sourceSnapshot.QueryRowContext(ctx, `SELECT deployment_generation FROM deployments LIMIT 1`).Scan(&pinnedGeneration); err != nil {
		os.Remove(snapshotPath)
		return "", 0, err
	}
	destinationURL := &url.URL{Scheme: "file", Path: snapshotPath}
	query := destinationURL.Query()
	query.Set("mode", "rw")
	query.Set("_foreign_keys", "on")
	query.Set("_journal_mode", "DELETE")
	destinationURL.RawQuery = query.Encode()
	destination, err := sql.Open("sqlite3", destinationURL.String())
	if err != nil {
		os.Remove(snapshotPath)
		return "", 0, err
	}
	destination.SetMaxOpenConns(1)
	defer destination.Close()
	destinationConnection, err := destination.Conn(ctx)
	if err != nil {
		os.Remove(snapshotPath)
		return "", 0, err
	}
	defer destinationConnection.Close()
	// The source transaction already established SQLite's read snapshot. This
	// timestamp therefore cannot predate a row copied by a later backup step.
	recoveryPointMS := s.clock.Now().UnixMilli()
	err = destinationConnection.Raw(func(destinationDriver any) error {
		return source.Raw(func(sourceDriver any) error {
			destinationSQLite, ok := destinationDriver.(*sqlite3.SQLiteConn)
			if !ok {
				return errors.New("unexpected destination sqlite connection")
			}
			sourceSQLite, ok := sourceDriver.(*sqlite3.SQLiteConn)
			if !ok {
				return errors.New("unexpected source sqlite connection")
			}
			backup, err := destinationSQLite.Backup("main", sourceSQLite, "main")
			if err != nil {
				return err
			}
			for {
				done, err := backup.Step(256)
				if err != nil {
					backup.Close()
					return err
				}
				if done {
					return backup.Close()
				}
				select {
				case <-ctx.Done():
					backup.Close()
					return ctx.Err()
				case <-time.After(5 * time.Millisecond):
				}
			}
		})
	})
	if err != nil {
		os.Remove(snapshotPath)
		return "", 0, fmt.Errorf("create consistent sqlite backup: %w", err)
	}
	if err := os.Chmod(snapshotPath, 0o600); err != nil {
		os.Remove(snapshotPath)
		return "", 0, err
	}
	return snapshotPath, recoveryPointMS, nil
}

func inspectBackupSnapshot(ctx context.Context, path, recipientHash string, createdMS, recoveryPointMS int64) (BackupManifest, error) {
	var manifest BackupManifest
	if err := verifyFileHashInput(path); err != nil {
		return manifest, err
	}
	database, err := openSnapshotDatabase(path, true)
	if err != nil {
		return manifest, err
	}
	defer database.Close()
	if err := database.QueryRowContext(ctx, `SELECT id,deployment_generation,schema_version,registry_revision FROM deployments LIMIT 1`).Scan(&manifest.DeploymentID, &manifest.DeploymentGeneration, &manifest.SchemaVersion, &manifest.RegistryRevision); err != nil {
		return manifest, err
	}
	if err := database.QueryRowContext(ctx, `SELECT COALESCE(max(rowid),0) FROM source_frames`).Scan(&manifest.HighWater.SourceFrameRowID); err != nil {
		return manifest, err
	}
	if err := database.QueryRowContext(ctx, `SELECT COALESCE(max(rowid),0) FROM source_status`).Scan(&manifest.HighWater.SourceStatusRowID); err != nil {
		return manifest, err
	}
	if err := database.QueryRowContext(ctx, `SELECT COALESCE(max(rowid),0) FROM audit`).Scan(&manifest.HighWater.AuditRowID); err != nil {
		return manifest, err
	}
	size, digest, err := hashFile(path, LiveDataLimitBytes)
	if err != nil {
		return manifest, err
	}
	manifest.FormatVersion = backupFormatVersion
	manifest.CreatedMS = createdMS
	manifest.RecoveryPointMS = recoveryPointMS
	manifest.RecoveryRecipientSHA256 = recipientHash
	manifest.Database = BackupManifestEntry{Name: backupDatabaseName, Kind: "database", Bytes: size, SHA256: digest}
	return manifest, nil
}

func verifySQLiteSnapshot(ctx context.Context, path string, manifest BackupManifest) error {
	database, err := openSnapshotDatabase(path, true)
	if err != nil {
		return err
	}
	defer database.Close()
	var integrity string
	if err := database.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		return errors.New("sqlite integrity check failed")
	}
	rows, err := database.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return err
	}
	defer rows.Close()
	if rows.Next() {
		return errors.New("sqlite foreign-key check failed")
	}
	if err := rows.Err(); err != nil {
		return err
	}
	var deploymentID, generation, registry string
	var schemaVersion int64
	if err := database.QueryRowContext(ctx, `SELECT id,deployment_generation,schema_version,registry_revision FROM deployments LIMIT 1`).Scan(&deploymentID, &generation, &schemaVersion, &registry); err != nil {
		return err
	}
	if deploymentID != manifest.DeploymentID || generation != manifest.DeploymentGeneration || schemaVersion != manifest.SchemaVersion || registry != manifest.RegistryRevision {
		return errors.New("backup manifest does not match sqlite snapshot")
	}
	return nil
}

func openSnapshotDatabase(path string, readOnly bool) (*sql.DB, error) {
	fileURL := &url.URL{Scheme: "file", Path: path}
	query := fileURL.Query()
	query.Set("_foreign_keys", "on")
	query.Set("_busy_timeout", "2000")
	if readOnly {
		query.Set("mode", "ro")
		query.Set("_query_only", "on")
	} else {
		query.Set("mode", "rw")
		query.Set("_journal_mode", "DELETE")
		query.Set("_synchronous", "FULL")
	}
	fileURL.RawQuery = query.Encode()
	database, err := sql.Open("sqlite3", fileURL.String())
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	if err := database.Ping(); err != nil {
		database.Close()
		return nil, err
	}
	return database, nil
}

func hashFile(path string, maximum int64) (int64, string, error) {
	return hashFileBounded(path, maximum, false)
}

func hashFileBounded(path string, maximum int64, allowEmpty bool) (int64, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(file, maximum+1))
	if err != nil || size > maximum || (!allowEmpty && size == 0) {
		return 0, "", errors.New("backup input size is outside bound")
	}
	return size, hex.EncodeToString(hash.Sum(nil)), nil
}

func verifyFileHashInput(path string) error {
	return validateOwnedRegularFile(path, true)
}

func (s *Store) markBackupCompleted(ctx context.Context, deploymentID, expectedGeneration string, completedMS int64) error {
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := ensureBackupMaintenanceTx(ctx, tx, deploymentID, expectedGeneration, completedMS); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE maintenance SET last_backup_ms=CASE WHEN last_backup_ms IS NULL OR last_backup_ms<? THEN ? ELSE last_backup_ms END,updated_ms=max(updated_ms,?) WHERE deployment_id=? AND EXISTS(SELECT 1 FROM deployments WHERE id=? AND deployment_generation=? AND recovery_state='normal')`, completedMS, completedMS, completedMS, deploymentID, deploymentID, expectedGeneration)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return ErrGenerationConflict
	}
	return tx.Commit()
}

func (s *Store) ensureBackupMaintenance(ctx context.Context, deploymentID, expectedGeneration string, nowMS int64) error {
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := ensureBackupMaintenanceTx(ctx, tx, deploymentID, expectedGeneration, nowMS); err != nil {
		return err
	}
	return tx.Commit()
}

func ensureBackupMaintenanceTx(ctx context.Context, tx *sql.Tx, deploymentID, expectedGeneration string, nowMS int64) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO maintenance(deployment_id,retention_revision,rollup_watermark_ms,last_backup_ms,storage_state,recovery_journal_cursor,evaluator_cursor_json,updated_ms)
		SELECT id,1,0,NULL,'normal',NULL,'{}',? FROM deployments WHERE id=? AND deployment_generation=? AND recovery_state='normal'
		ON CONFLICT(deployment_id) DO NOTHING`, nowMS, deploymentID, expectedGeneration); err != nil {
		return err
	}
	var valid int
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM deployments WHERE id=? AND deployment_generation=? AND recovery_state='normal')`, deploymentID, expectedGeneration).Scan(&valid); err != nil {
		return err
	}
	if valid != 1 {
		return ErrGenerationConflict
	}
	return nil
}
