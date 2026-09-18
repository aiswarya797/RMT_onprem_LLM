package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

const (
	RawFrameRetention = 72 * time.Hour
	RollupRetention   = 30 * 24 * time.Hour
	MaxRetentionRows  = 5000
	retentionTxnLimit = 100 * time.Millisecond
)

type RetentionResult struct {
	RawFramesDeleted     int64
	MinuteRollupsDeleted int64
	HourRollupsDeleted   int64
	ProcessRowsDeleted   int64
	ModelRowsDeleted     int64
}

// PruneObservationRetention performs one short bounded maintenance transaction.
// Raw evidence is eligible only after its minute has a complete rollup. The
// newest raw observation before the cutoff remains as the predecessor for the
// next interval, so a counter delta is never fabricated across a retention
// boundary. The deployment's highest rowid is also retained as a bounded
// high-water sentinel. SQLite may otherwise reuse a deleted maximum rowid and
// make the late-frame cursor skip a newly admitted frame.
func (s *Store) PruneObservationRetention(ctx context.Context, deploymentID string, nowMS int64, maxRows int) (RetentionResult, error) {
	if deploymentID == "" || nowMS < 0 || maxRows < 1 || maxRows > MaxRetentionRows {
		return RetentionResult{}, errors.New("invalid retention request")
	}
	deadline := time.Now().Add(retentionTxnLimit)
	if current, ok := ctx.Deadline(); ok && current.Before(deadline) {
		deadline = current
	}
	bounded, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	release, err := s.acquireWrite(bounded)
	if err != nil {
		return RetentionResult{}, err
	}
	defer release()
	tx, err := s.db.BeginTx(bounded, nil)
	if err != nil {
		return RetentionResult{}, err
	}
	defer tx.Rollback()

	result := RetentionResult{}
	remaining := maxRows
	rawCutoff := nowMS - RawFrameRetention.Milliseconds()
	if rawCutoff > 0 {
		outcome, err := tx.ExecContext(bounded, `DELETE FROM source_frames WHERE rowid IN (
			SELECT f.rowid FROM source_frames f
			WHERE f.deployment_id=? AND COALESCE(f.aligned_ms,f.original_wall_ms)<?
			AND f.rowid!=(SELECT max(highwater.rowid) FROM source_frames highwater WHERE highwater.deployment_id=f.deployment_id)
			AND EXISTS (
				SELECT 1 FROM rollup_minutes r
				WHERE r.deployment_id=f.deployment_id AND r.host_id=f.host_id AND r.source_id=f.source_id
				AND r.minute_ms=(COALESCE(f.aligned_ms,f.original_wall_ms)/60000)*60000 AND r.complete=1
			)
			AND EXISTS (
				SELECT 1 FROM source_frames newer
				WHERE newer.deployment_id=f.deployment_id AND newer.host_id=f.host_id AND newer.source_id=f.source_id
				AND COALESCE(newer.aligned_ms,newer.original_wall_ms)<?
				AND (COALESCE(newer.aligned_ms,newer.original_wall_ms)>COALESCE(f.aligned_ms,f.original_wall_ms)
					OR (COALESCE(newer.aligned_ms,newer.original_wall_ms)=COALESCE(f.aligned_ms,f.original_wall_ms) AND newer.sequence>f.sequence))
			)
			ORDER BY COALESCE(f.aligned_ms,f.original_wall_ms),f.sequence LIMIT ?
		)`, deploymentID, rawCutoff, rawCutoff, remaining)
		if err != nil {
			return result, fmt.Errorf("prune rolled raw frames: %w", err)
		}
		result.RawFramesDeleted, _ = outcome.RowsAffected()
		remaining -= int(result.RawFramesDeleted)
	}

	rollupCutoff := nowMS - RollupRetention.Milliseconds()
	if remaining > 0 && rollupCutoff > 0 {
		deleted, err := deleteOldRollups(bounded, tx, "rollup_minutes", "minute_ms", deploymentID, rollupCutoff, remaining)
		if err != nil {
			return result, err
		}
		result.MinuteRollupsDeleted = deleted
		remaining -= int(deleted)
	}
	if remaining > 0 && rollupCutoff > 0 {
		deleted, err := deleteOldRollups(bounded, tx, "rollup_hours", "hour_ms", deploymentID, rollupCutoff, remaining)
		if err != nil {
			return result, err
		}
		result.HourRollupsDeleted = deleted
		remaining -= int(deleted)
	}
	if remaining > 0 && rollupCutoff > 0 {
		// Keep process identities for an extra aligned hour so every retained
		// boundary rollup remains selectable after its raw frame is pruned.
		outcome, err := tx.ExecContext(bounded, `DELETE FROM process_observations WHERE rowid IN (
			SELECT rowid FROM process_observations WHERE deployment_id=? AND observed_ms<? ORDER BY observed_ms LIMIT ?
		)`, deploymentID, rollupCutoff-int64(time.Hour/time.Millisecond), remaining)
		if err != nil {
			return result, fmt.Errorf("prune process observations: %w", err)
		}
		result.ProcessRowsDeleted, _ = outcome.RowsAffected()
		remaining -= int(result.ProcessRowsDeleted)
	}
	if remaining > 0 && rollupCutoff > 0 {
		outcome, err := tx.ExecContext(bounded, `DELETE FROM model_load_observations WHERE rowid IN (
			SELECT rowid FROM model_load_observations WHERE deployment_id=? AND observed_ms<? ORDER BY observed_ms LIMIT ?
		)`, deploymentID, rollupCutoff-int64(time.Hour/time.Millisecond), remaining)
		if err != nil {
			return result, fmt.Errorf("prune model observations: %w", err)
		}
		result.ModelRowsDeleted, _ = outcome.RowsAffected()
	}
	if err := tx.Commit(); err != nil {
		return RetentionResult{}, err
	}
	return result, nil
}

// deleteOldRollups accepts only internal constants chosen by the caller. The
// identifiers are never derived from configuration or a request.
func deleteOldRollups(ctx context.Context, tx *sql.Tx, table, timeColumn, deploymentID string, cutoff int64, limit int) (int64, error) {
	query := fmt.Sprintf(`DELETE FROM %s WHERE rowid IN (SELECT rowid FROM %s WHERE deployment_id=? AND %s<? ORDER BY %s LIMIT ?)`, table, table, timeColumn, timeColumn)
	result, err := tx.ExecContext(ctx, query, deploymentID, cutoff, limit)
	if err != nil {
		return 0, fmt.Errorf("prune %s: %w", table, err)
	}
	deleted, err := result.RowsAffected()
	return deleted, err
}
