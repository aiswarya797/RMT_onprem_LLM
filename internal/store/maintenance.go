package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	RollupWatermarkDelay       = 60 * time.Second
	DefaultMinuteIntervalsTick = 8
	DefaultHourRollupsTick     = 2
	DefaultLateFramesTick      = 128
)

type MaintenanceLimits struct {
	MinuteIntervals int
	HourRollups     int
	LateFrames      int
	RetentionRows   int
}

type MaintenanceResult struct {
	WatermarkMS           int64
	MinuteRollupsWritten  int
	HourRollupsWritten    int
	LateMinutesRecomputed int
	LateFramesUnmergeable int
	Retention             RetentionResult
	SQLiteLogicalBytes    int64
	SQLiteReusableBytes   int64
	WALBusy               bool
	WALFrames             int
	WALFramesCheckpointed int
}

type maintenanceSource struct {
	HostID, SourceID string
}

type dirtyRollup struct {
	maintenanceSource
	MinuteMS int64
}

// RunMaintenance performs one bounded, synchronous maintenance pass. The hub
// owns cadence and cancellation; this method creates no worker or goroutine.
// It finalizes minutes 60 seconds behind hub time, builds hours only from 60
// compatible minutes, then prunes behind complete rollups.
func (s *Store) RunMaintenance(ctx context.Context, deploymentID string, nowMS int64, limits MaintenanceLimits) (MaintenanceResult, error) {
	if deploymentID == "" || nowMS < 0 || !validMaintenanceLimits(limits) {
		return MaintenanceResult{}, errors.New("invalid maintenance request")
	}
	state, err := s.readMaintenanceState(ctx, deploymentID, nowMS)
	if err != nil {
		return MaintenanceResult{}, err
	}
	result := MaintenanceResult{WatermarkMS: state.watermark}
	finalizedEnd := (nowMS - RollupWatermarkDelay.Milliseconds()) / 60_000 * 60_000
	if finalizedEnd < 0 {
		finalizedEnd = 0
	}

	dirty, nextFrameCursor, unmergeable, err := s.readDirtyRollups(ctx, deploymentID, state.frameCursor, state.watermark, nowMS, limits.LateFrames)
	if err != nil {
		return result, err
	}
	result.LateFramesUnmergeable = unmergeable
	for _, item := range dirty {
		revision, err := s.nextRollupRevision(ctx, RollupMinute, deploymentID, item.HostID, item.SourceID, item.MinuteMS)
		if err != nil {
			return result, err
		}
		if _, err := s.BuildAndPutMinuteRollup(ctx, deploymentID, item.HostID, item.SourceID, item.MinuteMS, revision); err != nil {
			return result, err
		}
		result.MinuteRollupsWritten++
		result.LateMinutesRecomputed++
	}

	watermark := state.watermark
	if watermark == 0 {
		if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(min((COALESCE(aligned_ms,original_wall_ms)/60000)*60000),?) FROM source_frames WHERE deployment_id=?`, finalizedEnd, deploymentID).Scan(&watermark); err != nil {
			return result, err
		}
	}
	for interval := 0; interval < limits.MinuteIntervals && watermark < finalizedEnd; interval++ {
		sources, err := s.sourcesForRollupInterval(ctx, deploymentID, watermark)
		if err != nil {
			return result, err
		}
		for _, source := range sources {
			revision, err := s.nextRollupRevision(ctx, RollupMinute, deploymentID, source.HostID, source.SourceID, watermark)
			if err != nil {
				return result, err
			}
			if _, err := s.BuildAndPutMinuteRollup(ctx, deploymentID, source.HostID, source.SourceID, watermark, revision); err != nil {
				return result, err
			}
			result.MinuteRollupsWritten++
		}
		watermark += 60_000
	}
	result.WatermarkMS = watermark

	// Minute writes invalidate their containing hour in the same transaction.
	// Rediscovering absent, complete hours from durable minute rows means a
	// bounded pass cannot lose work when more candidates exist than this tick's
	// budget or the process stops between ticks.
	hourKeys, err := s.pendingHourRollups(ctx, deploymentID, finalizedEnd, limits.HourRollups)
	if err != nil {
		return result, err
	}
	for _, item := range hourKeys {
		revision, err := s.nextRollupRevision(ctx, RollupHour, deploymentID, item.HostID, item.SourceID, item.MinuteMS)
		if err != nil {
			return result, err
		}
		if _, err := s.BuildAndPutHourRollup(ctx, deploymentID, item.HostID, item.SourceID, item.MinuteMS, revision); err != nil {
			if errors.Is(err, ErrRollupIncomplete) {
				continue
			}
			return result, err
		}
		result.HourRollupsWritten++
	}

	if err := s.writeMaintenanceState(ctx, deploymentID, watermark, nextFrameCursor, nowMS); err != nil {
		return result, err
	}
	result.Retention, err = s.PruneObservationRetention(ctx, deploymentID, nowMS, limits.RetentionRows)
	if err != nil {
		return result, err
	}
	result.SQLiteLogicalBytes, result.SQLiteReusableBytes, result.WALBusy, result.WALFrames, result.WALFramesCheckpointed, err = s.checkpointCapacity(ctx)
	return result, err
}

func (s *Store) pendingHourRollups(ctx context.Context, deploymentID string, finalizedEnd int64, limit int) ([]dirtyRollup, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT m.host_id,m.source_id,(m.minute_ms/3600000)*3600000 AS bucket_ms
		FROM rollup_minutes m
		LEFT JOIN rollup_hours h ON h.deployment_id=m.deployment_id AND h.host_id=m.host_id AND h.source_id=m.source_id AND h.hour_ms=(m.minute_ms/3600000)*3600000
		WHERE m.deployment_id=? AND m.complete=1 AND h.hour_ms IS NULL
		GROUP BY m.host_id,m.source_id,bucket_ms
		HAVING count(*)=60 AND min(m.minute_ms)=bucket_ms AND max(m.minute_ms)=bucket_ms+3540000 AND bucket_ms+3600000<=?
		ORDER BY bucket_ms,m.host_id,m.source_id LIMIT ?`, deploymentID, finalizedEnd, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]dirtyRollup, 0, limit)
	for rows.Next() {
		var item dirtyRollup
		if err := rows.Scan(&item.HostID, &item.SourceID, &item.MinuteMS); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func DefaultMaintenanceLimits() MaintenanceLimits {
	return MaintenanceLimits{MinuteIntervals: DefaultMinuteIntervalsTick, HourRollups: DefaultHourRollupsTick, LateFrames: DefaultLateFramesTick, RetentionRows: MaxRetentionRows}
}

func validMaintenanceLimits(value MaintenanceLimits) bool {
	return value.MinuteIntervals >= 1 && value.MinuteIntervals <= 60 && value.HourRollups >= 1 && value.HourRollups <= 8 && value.LateFrames >= 1 && value.LateFrames <= 1024 && value.RetentionRows >= 1 && value.RetentionRows <= MaxRetentionRows
}

type persistedMaintenance struct {
	watermark   int64
	frameCursor int64
}

func (s *Store) readMaintenanceState(ctx context.Context, deploymentID string, nowMS int64) (persistedMaintenance, error) {
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return persistedMaintenance{}, err
	}
	defer release()
	if _, err := s.db.ExecContext(ctx, `INSERT INTO maintenance(deployment_id,retention_revision,rollup_watermark_ms,last_backup_ms,storage_state,recovery_journal_cursor,evaluator_cursor_json,updated_ms) VALUES(?,1,0,NULL,'normal',NULL,'{}',?) ON CONFLICT(deployment_id) DO NOTHING`, deploymentID, nowMS); err != nil {
		return persistedMaintenance{}, err
	}
	var state persistedMaintenance
	var cursorJSON string
	if err := s.db.QueryRowContext(ctx, `SELECT rollup_watermark_ms,evaluator_cursor_json FROM maintenance WHERE deployment_id=?`, deploymentID).Scan(&state.watermark, &cursorJSON); err != nil {
		return persistedMaintenance{}, err
	}
	var cursor map[string]json.RawMessage
	if err := json.Unmarshal([]byte(cursorJSON), &cursor); err != nil {
		return persistedMaintenance{}, errors.New("invalid maintenance cursor")
	}
	if raw := cursor["rollup_frame_rowid"]; raw != nil && json.Unmarshal(raw, &state.frameCursor) != nil {
		return persistedMaintenance{}, errors.New("invalid rollup maintenance cursor")
	}
	return state, nil
}

func (s *Store) writeMaintenanceState(ctx context.Context, deploymentID string, watermark, frameCursor, nowMS int64) error {
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return err
	}
	defer release()
	var existing string
	if err := s.db.QueryRowContext(ctx, `SELECT evaluator_cursor_json FROM maintenance WHERE deployment_id=?`, deploymentID).Scan(&existing); err != nil {
		return err
	}
	var cursor map[string]json.RawMessage
	if err := json.Unmarshal([]byte(existing), &cursor); err != nil {
		return errors.New("invalid maintenance cursor")
	}
	if cursor == nil {
		cursor = make(map[string]json.RawMessage)
	}
	encodedFrameCursor, _ := json.Marshal(frameCursor)
	cursor["rollup_frame_rowid"] = encodedFrameCursor
	cursorJSON, _ := json.Marshal(cursor)
	_, err = s.db.ExecContext(ctx, `UPDATE maintenance SET rollup_watermark_ms=?,evaluator_cursor_json=?,updated_ms=? WHERE deployment_id=?`, watermark, string(cursorJSON), nowMS, deploymentID)
	return err
}

func (s *Store) readDirtyRollups(ctx context.Context, deploymentID string, frameCursor, watermark, nowMS int64, limit int) ([]dirtyRollup, int64, int, error) {
	if watermark == 0 {
		var currentMax int64
		if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(max(rowid),0) FROM source_frames WHERE deployment_id=?`, deploymentID).Scan(&currentMax); err != nil {
			return nil, frameCursor, 0, err
		}
		return nil, currentMax, 0, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT rowid,host_id,source_id,(COALESCE(aligned_ms,original_wall_ms)/60000)*60000 FROM source_frames WHERE deployment_id=? AND rowid>? AND COALESCE(aligned_ms,original_wall_ms)<? ORDER BY rowid LIMIT ?`, deploymentID, frameCursor, watermark, limit)
	if err != nil {
		return nil, frameCursor, 0, err
	}
	defer rows.Close()
	seen := make(map[dirtyRollup]bool)
	result := make([]dirtyRollup, 0)
	lastRowID := frameCursor
	unmergeable := 0
	cutoff := nowMS - RawFrameRetention.Milliseconds()
	for rows.Next() {
		var item dirtyRollup
		if err := rows.Scan(&lastRowID, &item.HostID, &item.SourceID, &item.MinuteMS); err != nil {
			return nil, frameCursor, 0, err
		}
		if item.MinuteMS < cutoff {
			unmergeable++
			continue
		}
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, frameCursor, 0, err
	}
	return result, lastRowID, unmergeable, nil
}

func (s *Store) sourcesForRollupInterval(ctx context.Context, deploymentID string, minuteMS int64) ([]maintenanceSource, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT s.host_id,s.id FROM sources s WHERE s.deployment_id=? AND s.kind IN ('host','runtime') AND ((s.created_ms<? AND (s.retired_ms IS NULL OR s.retired_ms>=?)) OR EXISTS (SELECT 1 FROM source_frames f WHERE f.deployment_id=s.deployment_id AND f.host_id=s.host_id AND f.source_id=s.id AND COALESCE(f.aligned_ms,f.original_wall_ms)>=? AND COALESCE(f.aligned_ms,f.original_wall_ms)<?)) ORDER BY s.host_id,s.id LIMIT 5`, deploymentID, minuteMS+60_000, minuteMS, minuteMS, minuteMS+60_000)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]maintenanceSource, 0, 4)
	for rows.Next() {
		var value maintenanceSource
		if err := rows.Scan(&value.HostID, &value.SourceID); err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	if len(result) > 4 {
		return nil, errors.New("supported passive source limit exceeded")
	}
	return result, rows.Err()
}

func (s *Store) nextRollupRevision(ctx context.Context, resolution, deploymentID, hostID, sourceID string, intervalMS int64) (int64, error) {
	table, err := rollupTable(resolution)
	if err != nil {
		return 0, err
	}
	query := fmt.Sprintf(`SELECT revision FROM %s WHERE deployment_id=? AND host_id=? AND source_id=? AND %s=?`, table.name, table.timeColumn)
	var revision int64
	err = s.db.QueryRowContext(ctx, query, deploymentID, hostID, sourceID, intervalMS).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		return 1, nil
	}
	return revision + 1, err
}

func (s *Store) checkpointCapacity(ctx context.Context) (logicalBytes, reusableBytes int64, busy bool, walFrames, checkpointed int, err error) {
	var pages, reusable, pageSize int64
	if err = s.db.QueryRowContext(ctx, `PRAGMA page_count`).Scan(&pages); err != nil {
		return
	}
	if err = s.db.QueryRowContext(ctx, `PRAGMA freelist_count`).Scan(&reusable); err != nil {
		return
	}
	if err = s.db.QueryRowContext(ctx, `PRAGMA page_size`).Scan(&pageSize); err != nil {
		return
	}
	var busyInt int
	if err = s.db.QueryRowContext(ctx, `PRAGMA wal_checkpoint(PASSIVE)`).Scan(&busyInt, &walFrames, &checkpointed); err != nil {
		return
	}
	logicalBytes, reusableBytes, busy = pages*pageSize, reusable*pageSize, busyInt != 0
	return
}
