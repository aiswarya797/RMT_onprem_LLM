package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type RestoreOptions struct {
	BackupPath                    string
	RecoveryKeyPath               string
	OutputDatabasePath            string
	OutputDataDirectory           string
	ConfirmDeploymentID           string
	ConfirmRecoveryPointMS        int64
	NewDeploymentGeneration       string
	NewCAFingerprintSHA256        string
	InstallingUserUID             int
	NowMS                         int64
	HubStopped                    bool
	DisplacedCopyPreserved        bool
	AcknowledgedDisplacedCopyLoss bool
}

type RestorePreparation struct {
	Manifest                BackupManifest
	ManifestSHA256          string
	NewDeploymentGeneration string
	ArchivedUsers           int64
	NewlyArchivedUsers      int64
	SupersededOutboxRows    int64
	ReenrollmentRequired    bool
	PreparedDataDirectory   string
}

// RestoreBackup prepares and publishes a new database file only. The caller
// must prove the hub is stopped, preserve the displaced live database (or carry
// an explicit reviewed loss acknowledgement), install the returned file, and
// mint/install the new CA named by NewCAFingerprintSHA256. This function never
// overwrites the live database or activates old trust material.
func RestoreBackup(ctx context.Context, options RestoreOptions) (RestorePreparation, error) {
	var empty RestorePreparation
	if !options.HubStopped || (!options.DisplacedCopyPreserved && !options.AcknowledgedDisplacedCopyLoss) || options.InstallingUserUID < 0 || options.NowMS < 0 || options.ConfirmRecoveryPointMS < 0 || !validUUIDText(options.ConfirmDeploymentID) || !validUUIDText(options.NewDeploymentGeneration) || !sha256HexPattern.MatchString(options.NewCAFingerprintSHA256) {
		return empty, errors.New("invalid or incomplete offline restore boundary")
	}
	if err := validateNewAbsolutePath(options.OutputDatabasePath); err != nil {
		return empty, err
	}
	if err := createExclusivePrivateDirectory(options.OutputDataDirectory); err != nil {
		return empty, err
	}
	keepDataDirectory := false
	defer func() {
		if !keepDataDirectory {
			os.RemoveAll(options.OutputDataDirectory)
		}
	}()
	verification, databasePath, err := decryptBackupToStaging(ctx, options.BackupPath, options.RecoveryKeyPath, filepath.Dir(options.OutputDatabasePath), options.OutputDataDirectory)
	if err != nil {
		return empty, err
	}
	defer os.Remove(databasePath)
	manifest := verification.Manifest
	if manifest.DeploymentID != options.ConfirmDeploymentID || manifest.RecoveryPointMS != options.ConfirmRecoveryPointMS || manifest.DeploymentGeneration == options.NewDeploymentGeneration || options.NowMS < manifest.CreatedMS {
		return empty, ErrGenerationConflict
	}
	if err := verifySQLiteSnapshot(ctx, databasePath, manifest); err != nil {
		return empty, err
	}
	archivedUsers, newlyArchivedUsers, supersededOutbox, err := resetRestoredTrust(ctx, databasePath, options)
	if err != nil {
		return empty, err
	}
	if err := verifyRestoredTrustState(ctx, databasePath, options.ConfirmDeploymentID, options.NewDeploymentGeneration, options.ConfirmRecoveryPointMS, archivedUsers); err != nil {
		return empty, err
	}
	if err := publishExclusive(databasePath, options.OutputDatabasePath); err != nil {
		return empty, err
	}
	keepDataDirectory = true
	return RestorePreparation{
		Manifest:                manifest,
		ManifestSHA256:          verification.ManifestSHA256,
		NewDeploymentGeneration: options.NewDeploymentGeneration,
		ArchivedUsers:           archivedUsers,
		NewlyArchivedUsers:      newlyArchivedUsers,
		SupersededOutboxRows:    supersededOutbox,
		ReenrollmentRequired:    true,
		PreparedDataDirectory:   options.OutputDataDirectory,
	}, nil
}

func resetRestoredTrust(ctx context.Context, databasePath string, options RestoreOptions) (int64, int64, int64, error) {
	database, err := openSnapshotDatabase(databasePath, false)
	if err != nil {
		return 0, 0, 0, err
	}
	defer database.Close()
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, 0, err
	}
	defer tx.Rollback()
	var currentGeneration, recoveryState string
	if err := tx.QueryRowContext(ctx, `SELECT deployment_generation,recovery_state FROM deployments WHERE id=?`, options.ConfirmDeploymentID).Scan(&currentGeneration, &recoveryState); err != nil {
		return 0, 0, 0, err
	}
	if currentGeneration == options.NewDeploymentGeneration || recoveryState != "normal" {
		return 0, 0, 0, ErrGenerationConflict
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO deployment_generations(deployment_id,generation,reason,activated_ms) VALUES(?,?,'restore_bootstrap',?)`, options.ConfirmDeploymentID, options.NewDeploymentGeneration, options.NowMS); err != nil {
		return 0, 0, 0, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE deployments SET deployment_generation=?,recovery_state='restore_requires_bootstrap',updated_ms=? WHERE id=? AND deployment_generation=? AND recovery_state='normal'`, options.NewDeploymentGeneration, options.NowMS, options.ConfirmDeploymentID, currentGeneration); err != nil {
		return 0, 0, 0, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO restore_bootstrap_transitions(deployment_id,deployment_generation,installing_user_uid,hub_stopped,state,archived_user_count,started_ms,completed_ms) VALUES(?,?,?,1,'archiving_restored_users',0,?,NULL)`, options.ConfirmDeploymentID, options.NewDeploymentGeneration, options.InstallingUserUID, options.NowMS); err != nil {
		return 0, 0, 0, err
	}
	users, err := tx.ExecContext(ctx, `UPDATE users SET disabled=1,historical_restored=1,version=version+1,updated_ms=? WHERE deployment_id=? AND historical_restored=0`, options.NowMS, options.ConfirmDeploymentID)
	if err != nil {
		return 0, 0, 0, err
	}
	newlyArchivedUsers, _ := users.RowsAffected()
	var archivedUsers int64
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE deployment_id=? AND historical_restored=1`, options.ConfirmDeploymentID).Scan(&archivedUsers); err != nil {
		return 0, 0, 0, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE restore_bootstrap_transitions SET archived_user_count=? WHERE deployment_id=? AND deployment_generation=?`, archivedUsers, options.ConfirmDeploymentID, options.NewDeploymentGeneration); err != nil {
		return 0, 0, 0, err
	}
	if err := writeRestoreRecoveryPoint(ctx, tx, options.ConfirmDeploymentID, options.ConfirmRecoveryPointMS, options.NowMS); err != nil {
		return 0, 0, 0, err
	}
	statements := []string{
		`UPDATE user_sessions SET revoked_ms=COALESCE(revoked_ms,?) WHERE deployment_id=?`,
		`UPDATE api_tokens SET revoked_ms=COALESCE(revoked_ms,?) WHERE deployment_id=?`,
		`UPDATE auth_bootstrap_tokens SET consumed_ms=COALESCE(consumed_ms,?) WHERE deployment_id=?`,
		`UPDATE collector_credentials SET revoked_ms=COALESCE(revoked_ms,?) WHERE deployment_id=?`,
		`UPDATE collector_enrollments SET consumed_ms=COALESCE(consumed_ms,?) WHERE deployment_id=?`,
		`UPDATE collector_sessions SET superseded_ms=COALESCE(superseded_ms,?) WHERE deployment_id=?`,
		`UPDATE hosts SET current_session_generation=0,last_boot_id=NULL,retired_ms=COALESCE(retired_ms,?),updated_ms=? WHERE deployment_id=?`,
		`UPDATE destinations SET disabled_ms=COALESCE(disabled_ms,?),updated_ms=? WHERE deployment_id=?`,
		`UPDATE maintenance_windows SET cancelled_ms=COALESCE(cancelled_ms,?) WHERE deployment_id=?`,
		`UPDATE collector_requests SET state='expired' WHERE deployment_id=? AND state IN ('pending','delivered')`,
		`UPDATE alert_instances SET state='superseded' WHERE deployment_id=? AND state!='superseded'`,
	}
	for index, statement := range statements {
		var err error
		switch index {
		case 6:
			_, err = tx.ExecContext(ctx, statement, options.NowMS, options.NowMS, options.ConfirmDeploymentID)
		case 7:
			_, err = tx.ExecContext(ctx, statement, options.NowMS, options.NowMS, options.ConfirmDeploymentID)
		case 9, 10:
			_, err = tx.ExecContext(ctx, statement, options.ConfirmDeploymentID)
		default:
			_, err = tx.ExecContext(ctx, statement, options.NowMS, options.ConfirmDeploymentID)
		}
		if err != nil {
			return 0, 0, 0, err
		}
	}
	outbox, err := tx.ExecContext(ctx, `UPDATE outbox SET state='superseded_before_delivery',lease_until_ms=NULL,next_attempt_ms=NULL,last_error_code='restored_historical' WHERE deployment_id=? AND state NOT IN ('sent','expired','superseded_before_delivery')`, options.ConfirmDeploymentID)
	if err != nil {
		return 0, 0, 0, err
	}
	supersededOutbox, _ := outbox.RowsAffected()
	if err := tx.Commit(); err != nil {
		return 0, 0, 0, err
	}
	if _, err := database.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return 0, 0, 0, err
	}
	if err := database.Close(); err != nil {
		return 0, 0, 0, err
	}
	file, err := os.OpenFile(databasePath, os.O_RDWR, 0)
	if err != nil {
		return 0, 0, 0, err
	}
	defer file.Close()
	if err := file.Sync(); err != nil {
		return 0, 0, 0, err
	}
	return archivedUsers, newlyArchivedUsers, supersededOutbox, nil
}

func writeRestoreRecoveryPoint(ctx context.Context, tx *sql.Tx, deploymentID string, recoveryPointMS, nowMS int64) error {
	var encoded string
	if err := tx.QueryRowContext(ctx, `SELECT evaluator_cursor_json FROM maintenance WHERE deployment_id=?`, deploymentID).Scan(&encoded); err != nil {
		return err
	}
	var cursor map[string]json.RawMessage
	if json.Unmarshal([]byte(encoded), &cursor) != nil {
		return errors.New("invalid maintenance cursor during restore")
	}
	if cursor == nil {
		cursor = make(map[string]json.RawMessage)
	}
	cursor["restore_recovery_point_ms"], _ = json.Marshal(recoveryPointMS)
	updated, err := json.Marshal(cursor)
	if err != nil || len(updated) > 65536 {
		return errors.New("restore metadata exceeds maintenance cursor bound")
	}
	_, err = tx.ExecContext(ctx, `UPDATE maintenance SET evaluator_cursor_json=?,updated_ms=? WHERE deployment_id=?`, string(updated), nowMS, deploymentID)
	return err
}

func verifyRestoredTrustState(ctx context.Context, databasePath, deploymentID, generation string, recoveryPointMS, archivedUsers int64) error {
	database, err := openSnapshotDatabase(databasePath, true)
	if err != nil {
		return err
	}
	defer database.Close()
	var integrity string
	if err := database.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		return errors.New("restored sqlite integrity check failed")
	}
	rows, err := database.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return err
	}
	if rows.Next() {
		rows.Close()
		return errors.New("restored sqlite foreign-key check failed")
	}
	if err := rows.Close(); err != nil {
		return err
	}
	var state string
	if err := database.QueryRowContext(ctx, `SELECT recovery_state FROM deployments WHERE id=? AND deployment_generation=?`, deploymentID, generation).Scan(&state); err != nil || state != "restore_requires_bootstrap" {
		return errors.New("restored database did not enter bootstrap boundary")
	}
	var storedRecoveryPoint int64
	if err := database.QueryRowContext(ctx, `SELECT json_extract(evaluator_cursor_json,'$.restore_recovery_point_ms') FROM maintenance WHERE deployment_id=?`, deploymentID).Scan(&storedRecoveryPoint); err != nil || storedRecoveryPoint != recoveryPointMS {
		return errors.New("restored database recovery point is missing")
	}
	var activeUsers, actualArchived, unrevokedSessions, unrevokedCredentials, unsuppressedOutbox int64
	checks := []struct {
		query string
		value *int64
	}{
		{`SELECT count(*) FROM users WHERE deployment_id=? AND historical_restored=0`, &activeUsers},
		{`SELECT count(*) FROM users WHERE deployment_id=? AND historical_restored=1 AND disabled=1`, &actualArchived},
		{`SELECT count(*) FROM user_sessions WHERE deployment_id=? AND revoked_ms IS NULL`, &unrevokedSessions},
		{`SELECT count(*) FROM collector_credentials WHERE deployment_id=? AND revoked_ms IS NULL`, &unrevokedCredentials},
		{`SELECT count(*) FROM outbox WHERE deployment_id=? AND state NOT IN ('sent','expired','superseded_before_delivery')`, &unsuppressedOutbox},
	}
	for _, check := range checks {
		if err := database.QueryRowContext(ctx, check.query, deploymentID).Scan(check.value); err != nil {
			return err
		}
	}
	if activeUsers != 0 || actualArchived != archivedUsers || unrevokedSessions != 0 || unrevokedCredentials != 0 || unsuppressedOutbox != 0 {
		return errors.New("restored trust reset is incomplete")
	}
	return nil
}
