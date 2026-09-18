package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"rmt.local/monitor/internal/domain"
)

const MaxQueryFrameRows = 12001

const maxQueryPayloadBytes = 16 << 20

var ErrQueryLimit = errors.New("query frame limit exceeded")

type QueryInventory struct {
	Deployment           domain.DeploymentState
	Hosts                []QueryHost
	Targets              []QueryTarget
	Sources              []QuerySource
	Models               []QueryModel
	OpenIncidentCount    int
	ObservedRequestCount int
	HistoryFrameCount    int
}

type QueryHost struct {
	ID                       string
	DisplayName              string
	Local                    bool
	CollectorVersion         *string
	CurrentSessionGeneration int64
	LastBootID               *string
	CapabilitiesJSON         string
	RetiredMS                *int64
	CreatedMS                int64
	UpdatedMS                int64
}

type QueryTarget struct {
	ID, HostID, DisplayName, AdapterID, EndpointAlias string
	RetiredMS                                         *int64
	CreatedMS, UpdatedMS                              int64
}

type QuerySource struct {
	ID, HostID, Kind string
	TargetID         *string
	RetiredMS        *int64
}

type QueryModel struct {
	ID, HostID, TargetID, Alias string
	Digest                      *string
	CreatedMS                   int64
}

type QueryFrameFilter struct {
	DeploymentID string
	HostID       string
	SourceID     string
	StartMS      int64
	EndMS        int64
	CurrentOnly  bool
	Descending   bool
	Limit        int
}

type QueryFrame struct {
	HostID, SourceID, CollectorBootID, DeliveryMode string
	IncarnationID                                   *string
	SessionGeneration                               int64
	Sequence                                        int64
	OriginalWallMS                                  int64
	AlignedMS                                       *int64
	UncertaintyMS                                   *int64
	DurationMS                                      int64
	Quality                                         domain.Quality
	DefinitionRevision                              string
	Codec                                           string
	Payload                                         []byte
	AdmittedMS                                      int64
}

type QuerySourceStatus struct {
	HostID, CollectorBootID string
	SessionGeneration       int64
	Sequence                int64
	ObservedMS              int64
	PayloadJSON             string
	AdmittedMS              int64
}

// ReadQueryInventory returns one consistent read snapshot of the deployment
// and its bounded inventory. It never updates freshness or inventory state.
func (s *Store) ReadQueryInventory(ctx context.Context) (QueryInventory, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return QueryInventory{}, err
	}
	defer tx.Rollback()
	var result QueryInventory
	var recoveryPoint sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT d.id,d.deployment_generation,d.recovery_state,
		CASE WHEN json_type(m.evaluator_cursor_json,'$.restore_recovery_point_ms')='integer' THEN json_extract(m.evaluator_cursor_json,'$.restore_recovery_point_ms') END
		FROM deployments d LEFT JOIN maintenance m ON m.deployment_id=d.id ORDER BY d.created_ms LIMIT 1`).Scan(&result.Deployment.DeploymentID, &result.Deployment.DeploymentGeneration, &result.Deployment.RecoveryState, &recoveryPoint); err != nil {
		return result, err
	}
	result.Deployment.SchemaVersion = domain.SchemaVersion
	result.Deployment.RecoveryPointMS = nullableInt64Pointer(recoveryPoint)
	result.Deployment.MutationsAllowed = result.Deployment.RecoveryState == "normal"

	hostRows, err := tx.QueryContext(ctx, `SELECT h.id,h.display_name,EXISTS(SELECT 1 FROM audit a WHERE a.deployment_id=h.deployment_id AND a.resource_id=h.id AND a.action='collector.local_host.register'),h.collector_version,h.current_session_generation,h.last_boot_id,h.capabilities_json,h.retired_ms,h.created_ms,h.updated_ms FROM hosts h WHERE h.deployment_id=? ORDER BY (h.retired_ms IS NOT NULL),h.created_ms,h.id LIMIT 2`, result.Deployment.DeploymentID)
	if err != nil {
		return result, err
	}
	for hostRows.Next() {
		var host QueryHost
		var collectorVersion, boot sql.NullString
		var retired sql.NullInt64
		var local int
		if err := hostRows.Scan(&host.ID, &host.DisplayName, &local, &collectorVersion, &host.CurrentSessionGeneration, &boot, &host.CapabilitiesJSON, &retired, &host.CreatedMS, &host.UpdatedMS); err != nil {
			hostRows.Close()
			return result, err
		}
		host.Local = local != 0
		host.CollectorVersion, host.LastBootID, host.RetiredMS = nullableStringPointer(collectorVersion), nullableStringPointer(boot), nullableInt64Pointer(retired)
		result.Hosts = append(result.Hosts, host)
	}
	if err := hostRows.Close(); err != nil {
		return result, err
	}

	targetRows, err := tx.QueryContext(ctx, `SELECT id,host_id,display_name,adapter_id,endpoint_alias,retired_ms,created_ms,updated_ms FROM targets WHERE deployment_id=? ORDER BY (retired_ms IS NOT NULL),created_ms,id LIMIT 2`, result.Deployment.DeploymentID)
	if err != nil {
		return result, err
	}
	for targetRows.Next() {
		var target QueryTarget
		var retired sql.NullInt64
		if err := targetRows.Scan(&target.ID, &target.HostID, &target.DisplayName, &target.AdapterID, &target.EndpointAlias, &retired, &target.CreatedMS, &target.UpdatedMS); err != nil {
			targetRows.Close()
			return result, err
		}
		target.RetiredMS = nullableInt64Pointer(retired)
		result.Targets = append(result.Targets, target)
	}
	if err := targetRows.Close(); err != nil {
		return result, err
	}

	sourceRows, err := tx.QueryContext(ctx, `SELECT id,host_id,kind,target_id,retired_ms FROM sources WHERE deployment_id=? ORDER BY (retired_ms IS NOT NULL),created_ms,id LIMIT 16`, result.Deployment.DeploymentID)
	if err != nil {
		return result, err
	}
	for sourceRows.Next() {
		var source QuerySource
		var target sql.NullString
		var retired sql.NullInt64
		if err := sourceRows.Scan(&source.ID, &source.HostID, &source.Kind, &target, &retired); err != nil {
			sourceRows.Close()
			return result, err
		}
		source.TargetID, source.RetiredMS = nullableStringPointer(target), nullableInt64Pointer(retired)
		result.Sources = append(result.Sources, source)
	}
	if err := sourceRows.Close(); err != nil {
		return result, err
	}

	modelRows, err := tx.QueryContext(ctx, `SELECT m.id,m.host_id,m.target_id,m.served_alias,m.digest,m.created_ms FROM model_revisions m JOIN targets t ON t.deployment_id=m.deployment_id AND t.host_id=m.host_id AND t.id=m.target_id WHERE m.deployment_id=? ORDER BY (t.retired_ms IS NOT NULL),m.created_ms,m.id LIMIT 128`, result.Deployment.DeploymentID)
	if err != nil {
		return result, err
	}
	for modelRows.Next() {
		var model QueryModel
		var digest sql.NullString
		if err := modelRows.Scan(&model.ID, &model.HostID, &model.TargetID, &model.Alias, &digest, &model.CreatedMS); err != nil {
			modelRows.Close()
			return result, err
		}
		model.Digest = nullableStringPointer(digest)
		result.Models = append(result.Models, model)
	}
	if err := modelRows.Close(); err != nil {
		return result, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM incidents WHERE deployment_id=? AND workflow_state='open'`, result.Deployment.DeploymentID).Scan(&result.OpenIncidentCount); err != nil {
		return result, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM request_samples WHERE deployment_id=?`, result.Deployment.DeploymentID).Scan(&result.ObservedRequestCount); err != nil {
		return result, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM source_frames WHERE deployment_id=?`, result.Deployment.DeploymentID).Scan(&result.HistoryFrameCount); err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	if result.Hosts == nil {
		result.Hosts = []QueryHost{}
	}
	if result.Targets == nil {
		result.Targets = []QueryTarget{}
	}
	if result.Sources == nil {
		result.Sources = []QuerySource{}
	}
	if result.Models == nil {
		result.Models = []QueryModel{}
	}
	return result, nil
}

func (s *Store) ReadQueryFrames(ctx context.Context, filter QueryFrameFilter) ([]QueryFrame, error) {
	if filter.DeploymentID == "" || filter.StartMS < 0 || filter.EndMS <= filter.StartMS || filter.Limit < 1 || filter.Limit > MaxQueryFrameRows {
		return nil, errors.New("invalid bounded frame query")
	}
	query := `SELECT f.host_id,f.source_id,f.collector_boot_id,f.incarnation_id,f.session_generation,f.sequence,f.delivery_mode,f.original_wall_ms,f.aligned_ms,f.uncertainty_ms,f.duration_ms,f.quality,f.definition_revision,f.codec,f.payload,f.admitted_ms FROM source_frames f JOIN hosts h ON h.deployment_id=f.deployment_id AND h.id=f.host_id WHERE f.deployment_id=? AND COALESCE(f.aligned_ms,f.original_wall_ms)>=? AND COALESCE(f.aligned_ms,f.original_wall_ms)<?`
	args := []any{filter.DeploymentID, filter.StartMS, filter.EndMS}
	if filter.HostID != "" {
		query += ` AND f.host_id=?`
		args = append(args, filter.HostID)
	}
	if filter.SourceID != "" {
		query += ` AND f.source_id=?`
		args = append(args, filter.SourceID)
	}
	if filter.CurrentOnly {
		query += ` AND f.delivery_mode='current' AND f.session_generation=h.current_session_generation AND f.collector_boot_id=h.last_boot_id`
	}
	direction := "ASC"
	if filter.Descending {
		direction = "DESC"
	}
	query += ` ORDER BY COALESCE(f.aligned_ms,f.original_wall_ms) ` + direction + `,f.sequence ` + direction + ` LIMIT ?`
	args = append(args, filter.Limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]QueryFrame, 0)
	totalPayloadBytes := 0
	for rows.Next() {
		var frame QueryFrame
		var incarnation sql.NullString
		var aligned, uncertainty sql.NullInt64
		if err := rows.Scan(&frame.HostID, &frame.SourceID, &frame.CollectorBootID, &incarnation, &frame.SessionGeneration, &frame.Sequence, &frame.DeliveryMode, &frame.OriginalWallMS, &aligned, &uncertainty, &frame.DurationMS, &frame.Quality, &frame.DefinitionRevision, &frame.Codec, &frame.Payload, &frame.AdmittedMS); err != nil {
			return nil, err
		}
		frame.IncarnationID, frame.AlignedMS, frame.UncertaintyMS = nullableStringPointer(incarnation), nullableInt64Pointer(aligned), nullableInt64Pointer(uncertainty)
		totalPayloadBytes += len(frame.Payload)
		if totalPayloadBytes > maxQueryPayloadBytes {
			return nil, ErrQueryLimit
		}
		result = append(result, frame)
	}
	return result, rows.Err()
}

func (s *Store) ReadCurrentSourceStatuses(ctx context.Context, deploymentID string) ([]QuerySourceStatus, error) {
	if deploymentID == "" {
		return nil, errors.New("deployment id is required")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT ss.host_id,ss.collector_boot_id,ss.session_generation,ss.sequence,ss.observed_ms,ss.payload_json,ss.admitted_ms FROM source_status ss JOIN hosts h ON h.deployment_id=ss.deployment_id AND h.id=ss.host_id WHERE ss.deployment_id=? AND ss.session_generation=h.current_session_generation AND ss.collector_boot_id=h.last_boot_id AND ss.sequence=(SELECT max(newer.sequence) FROM source_status newer WHERE newer.deployment_id=ss.deployment_id AND newer.host_id=ss.host_id AND newer.collector_boot_id=ss.collector_boot_id) ORDER BY ss.host_id LIMIT 2`, deploymentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]QuerySourceStatus, 0, 2)
	for rows.Next() {
		var value QuerySourceStatus
		if err := rows.Scan(&value.HostID, &value.CollectorBootID, &value.SessionGeneration, &value.Sequence, &value.ObservedMS, &value.PayloadJSON, &value.AdmittedMS); err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

// HasCollectedFrames reports whether any observation has ever been durably
// admitted for this deployment. Source registration alone is not collection.
func (s *Store) HasCollectedFrames(ctx context.Context, deploymentID string) (bool, error) {
	if deploymentID == "" {
		return false, errors.New("deployment id is required")
	}
	var collected bool
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM source_frames WHERE deployment_id=? LIMIT 1)`, deploymentID).Scan(&collected); err != nil {
		return false, err
	}
	return collected, nil
}

func nullableStringPointer(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	return &value.String
}

func nullableInt64Pointer(value sql.NullInt64) *int64 {
	if !value.Valid {
		return nil
	}
	return &value.Int64
}

func (frame QueryFrame) ObservationMS() int64 {
	if frame.AlignedMS != nil {
		return *frame.AlignedMS
	}
	return frame.OriginalWallMS
}

func (frame QueryFrame) ValidateCodec() error {
	if frame.Codec != FrameCodec {
		return fmt.Errorf("unsupported frame codec %q", frame.Codec)
	}
	return nil
}
