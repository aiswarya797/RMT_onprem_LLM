package store

import (
	"context"
	"database/sql"
	"errors"
)

const maxHistoryIdentityRows = 129

var ErrHistoryScopeNotFound = errors.New("history scope not found")

type RetainedSourceScope struct {
	HostID, SourceID, Kind, DisplayName string
	TargetID                            *string
	Retired                             bool
	EarliestMS, LatestMS                int64
}

type RetainedProcessScope struct {
	HostID, SourceID, ProcessKey string
	TargetID                     *string
	Retired                      bool
	EarliestMS, LatestMS         int64
}

type RetainedModelScope struct {
	HostID, TargetID, ModelID, DisplayName string
	Retired                                bool
	EarliestMS, LatestMS                   int64
}

type HistoryCatalogData struct {
	EarliestMS *int64
	LatestMS   *int64
	Sources    []RetainedSourceScope
	Processes  []RetainedProcessScope
	Models     []RetainedModelScope
	Truncated  bool
}

// ReadHistoryCatalogData uses retained rows as its identity authority rather
// than the deliberately small live-inventory cap. The raw high-water sentinel
// is ignored after raw retention because it is no longer queryable.
func (s *Store) ReadHistoryCatalogData(ctx context.Context, deploymentID string, nowMS int64) (HistoryCatalogData, error) {
	if deploymentID == "" || nowMS < 0 {
		return HistoryCatalogData{}, errors.New("invalid history catalog request")
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return HistoryCatalogData{}, err
	}
	defer tx.Rollback()
	result := HistoryCatalogData{Sources: []RetainedSourceScope{}, Processes: []RetainedProcessScope{}, Models: []RetainedModelScope{}}
	var earliest, latest sql.NullInt64
	if err := tx.QueryRowContext(ctx, `WITH retained(start_ms,end_ms) AS (
		SELECT COALESCE(aligned_ms,original_wall_ms),COALESCE(aligned_ms,original_wall_ms)+1 FROM source_frames WHERE deployment_id=? AND COALESCE(aligned_ms,original_wall_ms)>=?
		UNION ALL SELECT minute_ms,minute_ms+60000 FROM rollup_minutes WHERE deployment_id=?
		UNION ALL SELECT hour_ms,hour_ms+3600000 FROM rollup_hours WHERE deployment_id=?
	) SELECT min(start_ms),max(end_ms) FROM retained`, deploymentID, nowMS-RawFrameRetention.Milliseconds(), deploymentID, deploymentID).Scan(&earliest, &latest); err != nil {
		return HistoryCatalogData{}, err
	}
	result.EarliestMS, result.LatestMS = nullableInt64Pointer(earliest), nullableInt64Pointer(latest)

	rows, err := tx.QueryContext(ctx, `WITH retained(host_id,source_id,start_ms,end_ms) AS (
		SELECT host_id,source_id,COALESCE(aligned_ms,original_wall_ms),COALESCE(aligned_ms,original_wall_ms)+1 FROM source_frames WHERE deployment_id=? AND COALESCE(aligned_ms,original_wall_ms)>=?
		UNION ALL SELECT host_id,source_id,minute_ms,minute_ms+60000 FROM rollup_minutes WHERE deployment_id=?
		UNION ALL SELECT host_id,source_id,hour_ms,hour_ms+3600000 FROM rollup_hours WHERE deployment_id=?
	), bounded AS (
		SELECT host_id,source_id,min(start_ms) earliest_ms,max(end_ms) latest_ms FROM retained GROUP BY host_id,source_id
	) SELECT b.host_id,b.source_id,s.kind,s.target_id,CASE WHEN s.kind='host' THEN h.display_name ELSE t.display_name END,
		(CASE WHEN s.retired_ms IS NOT NULL OR h.retired_ms IS NOT NULL OR t.retired_ms IS NOT NULL THEN 1 ELSE 0 END),b.earliest_ms,b.latest_ms
		FROM bounded b JOIN sources s ON s.deployment_id=? AND s.host_id=b.host_id AND s.id=b.source_id
		JOIN hosts h ON h.deployment_id=s.deployment_id AND h.id=s.host_id
		LEFT JOIN targets t ON t.deployment_id=s.deployment_id AND t.host_id=s.host_id AND t.id=s.target_id
		ORDER BY b.latest_ms DESC,b.source_id LIMIT ?`,
		deploymentID, nowMS-RawFrameRetention.Milliseconds(), deploymentID, deploymentID, deploymentID, maxHistoryIdentityRows)
	if err != nil {
		return HistoryCatalogData{}, err
	}
	for rows.Next() {
		var source RetainedSourceScope
		var target sql.NullString
		if err := rows.Scan(&source.HostID, &source.SourceID, &source.Kind, &target, &source.DisplayName, &source.Retired, &source.EarliestMS, &source.LatestMS); err != nil {
			rows.Close()
			return HistoryCatalogData{}, err
		}
		if len(result.Sources) == maxHistoryIdentityRows-1 {
			result.Truncated = true
			continue
		}
		source.TargetID = nullableStringPointer(target)
		result.Sources = append(result.Sources, source)
	}
	if err := closeRows(rows); err != nil {
		return HistoryCatalogData{}, err
	}

	processRows, err := tx.QueryContext(ctx, `SELECT p.host_id,p.source_id,p.process_key_sha256,p.target_id,
		(CASE WHEN h.retired_ms IS NOT NULL OR s.retired_ms IS NOT NULL OR t.retired_ms IS NOT NULL THEN 1 ELSE 0 END),min(p.observed_ms),max(p.observed_ms)
		FROM process_observations p JOIN hosts h ON h.deployment_id=p.deployment_id AND h.id=p.host_id
		JOIN sources s ON s.deployment_id=p.deployment_id AND s.host_id=p.host_id AND s.id=p.source_id
		LEFT JOIN targets t ON t.deployment_id=p.deployment_id AND t.host_id=p.host_id AND t.id=p.target_id
		WHERE p.deployment_id=? AND p.observed_ms>=? GROUP BY p.host_id,p.source_id,p.process_key_sha256,p.target_id
		ORDER BY max(p.observed_ms) DESC,p.process_key_sha256 LIMIT ?`, deploymentID, nowMS-RollupRetention.Milliseconds(), maxHistoryIdentityRows)
	if err != nil {
		return HistoryCatalogData{}, err
	}
	for processRows.Next() {
		var process RetainedProcessScope
		var target sql.NullString
		if err := processRows.Scan(&process.HostID, &process.SourceID, &process.ProcessKey, &target, &process.Retired, &process.EarliestMS, &process.LatestMS); err != nil {
			processRows.Close()
			return HistoryCatalogData{}, err
		}
		if len(result.Processes) == maxHistoryIdentityRows-1 {
			result.Truncated = true
			continue
		}
		process.TargetID = nullableStringPointer(target)
		result.Processes = append(result.Processes, process)
	}
	if err := closeRows(processRows); err != nil {
		return HistoryCatalogData{}, err
	}

	modelRows, err := tx.QueryContext(ctx, `SELECT o.host_id,o.target_id,o.model_id,m.served_alias,
		(h.retired_ms IS NOT NULL OR t.retired_ms IS NOT NULL),min(o.observed_ms),max(o.observed_ms)
		FROM model_load_observations o JOIN model_revisions m ON m.deployment_id=o.deployment_id AND m.host_id=o.host_id AND m.target_id=o.target_id AND m.id=o.model_id
		JOIN hosts h ON h.deployment_id=o.deployment_id AND h.id=o.host_id
		JOIN targets t ON t.deployment_id=o.deployment_id AND t.host_id=o.host_id AND t.id=o.target_id
		WHERE o.deployment_id=? AND o.observed_ms>=? GROUP BY o.host_id,o.target_id,o.model_id
		ORDER BY max(o.observed_ms) DESC,o.model_id LIMIT ?`, deploymentID, nowMS-RollupRetention.Milliseconds(), maxHistoryIdentityRows)
	if err != nil {
		return HistoryCatalogData{}, err
	}
	for modelRows.Next() {
		var model RetainedModelScope
		if err := modelRows.Scan(&model.HostID, &model.TargetID, &model.ModelID, &model.DisplayName, &model.Retired, &model.EarliestMS, &model.LatestMS); err != nil {
			modelRows.Close()
			return HistoryCatalogData{}, err
		}
		if len(result.Models) == maxHistoryIdentityRows-1 {
			result.Truncated = true
			continue
		}
		result.Models = append(result.Models, model)
	}
	if err := closeRows(modelRows); err != nil {
		return HistoryCatalogData{}, err
	}
	if err := tx.Commit(); err != nil {
		return HistoryCatalogData{}, err
	}
	return result, nil
}

func closeRows(rows *sql.Rows) error {
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	return rows.Close()
}

// ResolveHistorySource bypasses live inventory caps while remaining bounded to
// one exact retained scope identity. An empty requested window must not turn a
// known process into an unknown identity; sample queries apply the time bounds.
func (s *Store) ResolveHistorySource(ctx context.Context, deploymentID, scope, kind string, startMS, endMS int64) (QuerySource, error) {
	if deploymentID == "" || scope == "" || startMS < 0 || endMS <= startMS {
		return QuerySource{}, errors.New("invalid history source lookup")
	}
	query := `SELECT DISTINCT s.id,s.host_id,s.kind,s.target_id,s.retired_ms FROM sources s`
	args := []any{deploymentID}
	switch kind {
	case "host":
		query += ` WHERE s.deployment_id=? AND s.kind='host' AND s.host_id=?`
		args = append(args, scope)
	case "runtime":
		query += ` WHERE s.deployment_id=? AND s.kind='runtime' AND s.target_id=?`
		args = append(args, scope)
	case "model":
		query += ` JOIN model_revisions m ON m.deployment_id=s.deployment_id AND m.host_id=s.host_id AND m.target_id=s.target_id WHERE s.deployment_id=? AND s.kind='runtime' AND m.id=?`
		args = append(args, scope)
	case "process":
		query += ` JOIN process_observations p ON p.deployment_id=s.deployment_id AND p.host_id=s.host_id AND p.source_id=s.id WHERE s.deployment_id=? AND s.kind='host' AND p.process_key_sha256=?`
		args = append(args, scope)
	default:
		return QuerySource{}, errors.New("invalid history scope kind")
	}
	query += ` ORDER BY s.created_ms DESC,s.id LIMIT 1`
	var source QuerySource
	var target sql.NullString
	var retired sql.NullInt64
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&source.ID, &source.HostID, &source.Kind, &target, &retired); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return QuerySource{}, ErrHistoryScopeNotFound
		}
		return QuerySource{}, err
	}
	source.TargetID, source.RetiredMS = nullableStringPointer(target), nullableInt64Pointer(retired)
	return source, nil
}
