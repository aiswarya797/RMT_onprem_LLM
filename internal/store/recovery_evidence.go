package store

import (
	"context"
	"database/sql"
)

type RecoveryInterval struct {
	Class          string `json:"class"`
	RetainedRows   int64  `json:"retained_rows"`
	FirstHubTimeMS *int64 `json:"first_hub_time_ms"`
	LastHubTimeMS  *int64 `json:"last_hub_time_ms"`
}

type RecoveryEvidence struct {
	CurrentStateReadable bool                  `json:"current_state_readable"`
	SameGeneration       bool                  `json:"same_generation"`
	BackupHighWater      BackupHighWaterMarks  `json:"backup_high_water"`
	DisplacedHighWater   *BackupHighWaterMarks `json:"displaced_high_water"`
	KnownLaterRecords    []RecoveryInterval    `json:"known_later_records"`
}

// ReadRecoveryEvidence describes only surviving records newer than the backup's
// receipt boundaries. An empty result cannot prove zero loss: retention, in-place
// edits and already-pruned evidence remain unknown to this comparison.
func (s *Store) ReadRecoveryEvidence(ctx context.Context, manifest BackupManifest) (RecoveryEvidence, error) {
	result := RecoveryEvidence{BackupHighWater: manifest.HighWater, KnownLaterRecords: []RecoveryInterval{}}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	var deployment, generation string
	if err := tx.QueryRowContext(ctx, `SELECT id,deployment_generation FROM deployments LIMIT 1`).Scan(&deployment, &generation); err != nil {
		return result, err
	}
	if deployment != manifest.DeploymentID {
		return result, ErrOwnershipMismatch
	}
	marks := BackupHighWaterMarks{}
	checks := []struct {
		class, table, timeColumn string
		mark                     int64
		high                     *int64
	}{
		{"source_frames", "source_frames", "admitted_ms", manifest.HighWater.SourceFrameRowID, &marks.SourceFrameRowID},
		{"source_status", "source_status", "admitted_ms", manifest.HighWater.SourceStatusRowID, &marks.SourceStatusRowID},
		{"audit", "audit", "time_ms", manifest.HighWater.AuditRowID, &marks.AuditRowID},
	}
	for _, check := range checks {
		// Table/column names are the fixed allowlist above, never caller input.
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(max(rowid),0) FROM `+check.table+` WHERE deployment_id=?`, deployment).Scan(check.high); err != nil {
			return result, err
		}
		if generation != manifest.DeploymentGeneration {
			continue
		}
		interval := RecoveryInterval{Class: check.class}
		var first, last sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT count(*),min(`+check.timeColumn+`),max(`+check.timeColumn+`) FROM `+check.table+` WHERE deployment_id=? AND rowid>?`, deployment, check.mark).Scan(&interval.RetainedRows, &first, &last); err != nil {
			return result, err
		}
		if interval.RetainedRows > 0 {
			interval.FirstHubTimeMS = &first.Int64
			interval.LastHubTimeMS = &last.Int64
			result.KnownLaterRecords = append(result.KnownLaterRecords, interval)
		}
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	result.CurrentStateReadable = true
	result.SameGeneration = generation == manifest.DeploymentGeneration
	result.DisplacedHighWater = &marks
	return result, nil
}
