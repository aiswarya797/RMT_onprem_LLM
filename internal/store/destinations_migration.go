package store

import (
	"database/sql"
	"fmt"
)

// ensureNotificationStorage is the narrow additive bridge from the reviewed
// pre-dispatch schema. Full release upgrades still own numbered migrations;
// this keeps existing first-pass databases readable while U07 lands.
func (s *Store) ensureNotificationStorage() error {
	var destinations, outbox int
	if err := s.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='destinations'`).Scan(&destinations); err != nil {
		return err
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='outbox'`).Scan(&outbox); err != nil {
		return err
	}
	if destinations == 0 || outbox == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, column := range []struct{ table, name, declaration string }{
		{"destinations", "last_test_job_id", "TEXT"},
		{"outbox", "lease_token", "TEXT"},
		{"outbox", "destination_secret_ref", "TEXT"},
		{"outbox", "send_started_ms", "INTEGER"},
		{"outbox", "sent_ms", "INTEGER"},
		{"outbox", "receiver_ack_ms", "INTEGER"},
		{"outbox", "completed_ms", "INTEGER"},
		{"outbox", "accepted_unknown", "INTEGER NOT NULL DEFAULT 0 CHECK(accepted_unknown IN (0,1))"},
		{"outbox", "job_id", "TEXT"},
	} {
		exists, err := sqliteColumnExists(tx, column.table, column.name)
		if err != nil {
			return err
		}
		if !exists {
			if _, err := tx.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", column.table, column.name, column.declaration)); err != nil {
				return fmt.Errorf("add notification column %s.%s: %w", column.table, column.name, err)
			}
		}
	}
	if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS outbox_destination_history ON outbox(deployment_id,destination_id,created_ms,id)`); err != nil {
		return err
	}
	if err := migrateLegacyNotificationOutbox(tx, s.clock.Now().UnixMilli()); err != nil {
		return err
	}
	return tx.Commit()
}

// migrateLegacyNotificationOutbox preserves the only secret reference that a
// legacy row can prove. An edited destination is deliberately not a source of
// truth for an old delivery: those rows become terminal audit records instead
// of being sent with a guessed credential.
func migrateLegacyNotificationOutbox(tx *sql.Tx, now int64) error {
	if _, err := tx.Exec(`UPDATE outbox SET destination_secret_ref=(SELECT d.secret_ref FROM destinations d WHERE d.deployment_id=outbox.deployment_id AND d.id=outbox.destination_id AND d.version=outbox.destination_revision AND d.secret_ref IS NOT NULL AND length(d.secret_ref)=64 AND lower(d.secret_ref) NOT GLOB '*[^0-9a-f]*') WHERE destination_secret_ref IS NULL AND EXISTS (SELECT 1 FROM destinations d WHERE d.deployment_id=outbox.deployment_id AND d.id=outbox.destination_id AND d.version=outbox.destination_revision AND d.secret_ref IS NOT NULL AND length(d.secret_ref)=64 AND lower(d.secret_ref) NOT GLOB '*[^0-9a-f]*')`); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE outbox SET state='superseded_before_delivery',lease_token=NULL,lease_until_ms=NULL,next_attempt_ms=NULL,last_error_code='legacy_secret_reference_unavailable',completed_ms=?,accepted_unknown=CASE WHEN state='leased' THEN 1 ELSE accepted_unknown END WHERE destination_secret_ref IS NULL AND state IN ('pending','failed','muted','leased') AND (NOT EXISTS (SELECT 1 FROM destinations d WHERE d.deployment_id=outbox.deployment_id AND d.id=outbox.destination_id) OR EXISTS (SELECT 1 FROM destinations d WHERE d.deployment_id=outbox.deployment_id AND d.id=outbox.destination_id AND (d.version!=outbox.destination_revision OR d.secret_ref IS NOT NULL AND d.secret_ref!='' OR d.disabled_ms IS NOT NULL)))`, now); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE outbox SET state='failed',lease_token=NULL,lease_until_ms=NULL,next_attempt_ms=?,last_error_code='receiver_ack_unknown',accepted_unknown=1 WHERE state='leased' AND lease_token IS NULL AND destination_secret_ref IS NOT NULL AND expires_ms>?`, now, now); err != nil {
		return err
	}
	return nil
}

func sqliteColumnExists(tx *sql.Tx, table, column string) (bool, error) {
	rows, err := tx.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}
