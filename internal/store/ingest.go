package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
)

var ErrStatusObservationExpired = errors.New("source status observation expired before admission")

func (s *Store) IngestCollectorBatch(ctx context.Context, batch protocol.CollectorBatch) (protocol.BatchACK, error) {
	if err := batch.Validate(); err != nil {
		return protocol.BatchACK{}, err
	}
	select {
	case s.ingest <- struct{}{}:
		defer func() { <-s.ingest }()
	default:
		return protocol.BatchACK{}, ErrWriterBackpressure
	}
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return protocol.BatchACK{}, err
	}
	defer release()
	type encodedFrame struct {
		frame   protocol.CollectorFrame
		payload []byte
		hash    string
	}
	encoded := make([]encodedFrame, 0, len(batch.Frames))
	for _, frame := range batch.Frames {
		payload, hash, err := s.codec.Encode(frame)
		if err != nil {
			return protocol.BatchACK{}, err
		}
		encoded = append(encoded, encodedFrame{frame, payload, hash})
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return protocol.BatchACK{}, err
	}
	defer tx.Rollback()
	if err := validateBatchSession(ctx, tx, batch); err != nil {
		return protocol.BatchACK{}, err
	}
	now := s.clock.Now().UnixMilli()
	duplicates := 0
	pending := make([]encodedFrame, 0, len(encoded))
	payloadBytes := 0
	for _, item := range encoded {
		if err := validateFrameOwnership(ctx, tx, batch, item.frame); err != nil {
			return protocol.BatchACK{}, err
		}
		var existing string
		err := tx.QueryRowContext(ctx, `SELECT original_payload_sha256 FROM source_frames WHERE deployment_id=? AND host_id=? AND original_collector_boot_id=? AND original_source_id=? AND original_sequence=?`, batch.DeploymentID, batch.HostID, batch.CollectorBootID, item.frame.SourceID, item.frame.Sequence).Scan(&existing)
		if err == nil {
			if existing != item.hash {
				return protocol.BatchACK{}, ErrOwnershipMismatch
			}
			duplicates++
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return protocol.BatchACK{}, err
		}
		pending = append(pending, item)
		payloadBytes += len(item.payload)
	}
	if len(pending) > 0 {
		requestedBytes, err := batchCapacityBytes(payloadBytes, len(pending))
		if err != nil {
			return protocol.BatchACK{}, err
		}
		if err := s.capacityAdmissionTx(ctx, tx, batch.DeploymentID, now, requestedBytes); err != nil {
			return protocol.BatchACK{}, err
		}
	}
	accepted := 0
	for _, item := range pending {
		if batch.DeliveryMode == "current" {
			if err := s.validateCurrentFrameOrder(ctx, tx, batch, item.frame, now); err != nil {
				return protocol.BatchACK{}, err
			}
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO source_frames(deployment_id,host_id,security_generation,session_generation,collector_boot_id,source_id,sequence,delivery_mode,incarnation_id,original_wall_ms,aligned_ms,uncertainty_ms,duration_ms,quality,definition_revision,codec,payload,payload_sha256,original_security_generation,original_collector_boot_id,original_source_id,original_sequence,original_payload_sha256,recovery_grant_id,recovery_grant_hash,admitted_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,NULL,?)`, batch.DeploymentID, batch.HostID, batch.SecurityGeneration, batch.SessionGeneration, batch.CollectorBootID, item.frame.SourceID, item.frame.Sequence, batch.DeliveryMode, item.frame.IncarnationID, item.frame.ObservedWallMS, item.frame.EstimatedUTCMS, item.frame.UncertaintyMS, item.frame.DurationMS, string(item.frame.Quality), item.frame.DefinitionRevision, FrameCodec, item.payload, item.hash, batch.SecurityGeneration, batch.CollectorBootID, item.frame.SourceID, item.frame.Sequence, item.hash, now)
		if err != nil {
			return protocol.BatchACK{}, fmt.Errorf("insert source frame: %w", err)
		}
		if err := persistProcessObservations(ctx, tx, batch, item.frame, now); err != nil {
			return protocol.BatchACK{}, err
		}
		if err := persistModelObservations(ctx, tx, batch, item.frame); err != nil {
			return protocol.BatchACK{}, err
		}
		if err := s.persistConfigObservation(ctx, tx, batch, item.frame, now); err != nil {
			return protocol.BatchACK{}, err
		}
		accepted++
	}
	if err := tx.Commit(); err != nil {
		return protocol.BatchACK{}, err
	}
	return protocol.BatchACK{BatchID: batch.BatchID, Durable: true, Accepted: accepted, Duplicate: duplicates, HubTimeMS: now, NextSendAfterMS: 0, ControlRequests: []protocol.ControlRequest{}}, nil
}

func persistModelObservations(ctx context.Context, tx *sql.Tx, batch protocol.CollectorBatch, frame protocol.CollectorFrame) error {
	if len(frame.ModelObservations) == 0 {
		return nil
	}
	observedMS := frame.ObservedWallMS
	if frame.EstimatedUTCMS != nil {
		observedMS = *frame.EstimatedUTCMS
	}
	for _, model := range frame.ModelObservations {
		provenance, err := json.Marshal(model.Provenance)
		if err != nil {
			return fmt.Errorf("encode model provenance: %w", err)
		}
		state := "not_reported_loaded"
		if model.Loaded {
			state = "reported_loaded"
		}
		var size, vram any
		if model.ReportedSizeBytes != nil {
			size = string(*model.ReportedSizeBytes)
		}
		if model.ReportedSizeVRAMBytes != nil {
			vram = string(*model.ReportedSizeVRAMBytes)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO model_load_observations(deployment_id,host_id,target_id,model_id,observed_ms,state,reported_size_bytes,reported_size_vram_bytes,provenance_json)
			SELECT ?,?,target_id,?,?,?,?,?,? FROM sources WHERE deployment_id=? AND host_id=? AND id=? AND target_id IS NOT NULL ON CONFLICT DO NOTHING`,
			batch.DeploymentID, batch.HostID, model.ModelID, observedMS, state, size, vram, string(provenance), batch.DeploymentID, batch.HostID, frame.SourceID)
		if err != nil {
			return fmt.Errorf("insert model observation: %w", err)
		}
	}
	return nil
}

type configTransitionFields struct {
	BeforeConfigID string `json:"before_config_id"`
	AfterConfigID  string `json:"after_config_id"`
	BeforeHash     string `json:"before_hash"`
	AfterHash      string `json:"after_hash"`
}

type configBoundary struct {
	configID   string
	configHash string
	observedMS int64
}

type configUnavailableFields struct {
	CurrentConfigID string `json:"current_config_id"`
	CurrentHash     string `json:"current_hash"`
	Reason          string `json:"reason"`
}

func (s *Store) persistConfigObservation(ctx context.Context, tx *sql.Tx, batch protocol.CollectorBatch, frame protocol.CollectorFrame, admittedMS int64) error {
	observation := frame.ConfigObservation
	if observation == nil {
		return nil
	}
	fieldsJSON, err := json.Marshal(observation.Fields)
	if err != nil {
		return fmt.Errorf("encode config fields: %w", err)
	}
	provenanceJSON, err := json.Marshal(observation.FieldProvenance)
	if err != nil {
		return fmt.Errorf("encode config provenance: %w", err)
	}
	var hadConfigHistory bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM config_snapshots WHERE deployment_id=? AND host_id=? AND target_id=?)`, batch.DeploymentID, batch.HostID, observation.TargetID).Scan(&hadConfigHistory); err != nil {
		return err
	}
	boundary, predecessorVerified, err := s.verifiedConfigPredecessor(ctx, tx, batch, frame)
	if err != nil {
		return err
	}
	observedMS := effectiveFrameTime(frame)
	var configID, storedFields string
	err = tx.QueryRowContext(ctx, `SELECT id,fields_json FROM config_snapshots WHERE deployment_id=? AND host_id=? AND target_id=? AND config_hash=?`, batch.DeploymentID, batch.HostID, observation.TargetID, observation.ConfigHash).Scan(&configID, &storedFields)
	if errors.Is(err, sql.ErrNoRows) {
		configID, err = domain.NewUUID()
		if err != nil {
			return err
		}
		var preceding any
		if predecessorVerified {
			preceding = boundary.observedMS
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO config_snapshots(id,deployment_id,host_id,target_id,incarnation_id,config_hash,observed_ms,preceding_observed_ms,fields_json,provenance_json) VALUES(?,?,?,?,NULL,?,?,?,?,?)`, configID, batch.DeploymentID, batch.HostID, observation.TargetID, observation.ConfigHash, observedMS, preceding, string(fieldsJSON), string(provenanceJSON)); err != nil {
			return fmt.Errorf("insert config identity: %w", err)
		}
	} else if err != nil {
		return err
	} else if storedFields != string(fieldsJSON) {
		return ErrOwnershipMismatch
	}
	if !predecessorVerified {
		if batch.DeliveryMode == "current" && hadConfigHistory {
			return persistUnavailableConfigBoundary(ctx, tx, batch, observation, configID, observedMS, admittedMS, frame.EstimatedUTCMS == nil)
		}
		return nil
	}
	if boundary.configHash == observation.ConfigHash {
		return nil
	}
	fields := configTransitionFields{BeforeConfigID: boundary.configID, AfterConfigID: configID, BeforeHash: boundary.configHash, AfterHash: observation.ConfigHash}
	transitionJSON, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	eventProvenance, err := json.Marshal(observation.FieldProvenance.ServerVersion)
	if err != nil {
		return err
	}
	eventID, err := domain.NewUUID()
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO events(id,deployment_id,host_id,target_id,incarnation_id,occurred_start_ms,occurred_end_ms,detected_ms,code,severity,allowlisted_fields_json,source,provenance_json,repeat_count) VALUES(?,?,?,?,NULL,?,?,?,'config_change_detected','info',?,'runtime_api',?,1)`, eventID, batch.DeploymentID, batch.HostID, observation.TargetID, boundary.observedMS, observedMS, admittedMS, string(transitionJSON), string(eventProvenance)); err != nil {
		return fmt.Errorf("insert config transition: %w", err)
	}
	return nil
}

func persistUnavailableConfigBoundary(ctx context.Context, tx *sql.Tx, batch protocol.CollectorBatch, observation *domain.RuntimeConfigObservation, configID string, observedMS, admittedMS int64, alignmentUnavailable bool) error {
	reason := "cross_boot_predecessor_unavailable"
	if observation.PreviousConfigHash != nil {
		reason = "claimed_predecessor_unverified"
	} else if alignmentUnavailable {
		reason = "clock_alignment_unavailable"
	}
	fields, err := json.Marshal(configUnavailableFields{CurrentConfigID: configID, CurrentHash: observation.ConfigHash, Reason: reason})
	if err != nil {
		return err
	}
	provenance, err := json.Marshal(observation.FieldProvenance.ServerVersion)
	if err != nil {
		return err
	}
	eventID, err := domain.NewUUID()
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO events(id,deployment_id,host_id,target_id,incarnation_id,occurred_start_ms,occurred_end_ms,detected_ms,code,severity,allowlisted_fields_json,source,provenance_json,repeat_count) VALUES(?,?,?,?,NULL,?,?,?,'config_transition_unavailable','unknown',?,'hub',?,1)`, eventID, batch.DeploymentID, batch.HostID, observation.TargetID, observedMS, observedMS, admittedMS, string(fields), string(provenance))
	return err
}

func effectiveFrameTime(frame protocol.CollectorFrame) int64 {
	if frame.EstimatedUTCMS != nil {
		return *frame.EstimatedUTCMS
	}
	return frame.ObservedWallMS
}

// verifiedConfigPredecessor accepts a collector boundary only when the exact
// prior config observation is already durable under the same source and boot.
// Out-of-order replay therefore loses a transition claim rather than inventing
// one across an unknown restart or loss interval.
func (s *Store) verifiedConfigPredecessor(ctx context.Context, tx *sql.Tx, batch protocol.CollectorBatch, frame protocol.CollectorFrame) (configBoundary, bool, error) {
	observation := frame.ConfigObservation
	if observation == nil {
		return configBoundary{}, false, nil
	}
	if observation.PreviousConfigHash == nil || observation.PreviousObservedMS == nil {
		if batch.DeliveryMode != "current" || frame.EstimatedUTCMS == nil {
			return configBoundary{}, false, nil
		}
		return s.verifiedCrossBootConfigPredecessor(ctx, tx, batch, frame)
	}
	rows, err := tx.QueryContext(ctx, `SELECT original_collector_boot_id,original_sequence,payload FROM source_frames WHERE deployment_id=? AND host_id=? AND original_source_id=? AND original_wall_ms=? ORDER BY admitted_ms DESC LIMIT 16`, batch.DeploymentID, batch.HostID, frame.SourceID, *observation.PreviousObservedMS)
	if err != nil {
		return configBoundary{}, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var bootID string
		var sequence int64
		var payload []byte
		if err := rows.Scan(&bootID, &sequence, &payload); err != nil {
			return configBoundary{}, false, err
		}
		if bootID != batch.CollectorBootID || sequence >= frame.Sequence {
			continue
		}
		previous, err := s.codec.Decode(payload)
		if err != nil {
			return configBoundary{}, false, err
		}
		if previous.ConfigObservation == nil || previous.ConfigObservation.TargetID != observation.TargetID || previous.ConfigObservation.ConfigHash != *observation.PreviousConfigHash || previous.ObservedWallMS != *observation.PreviousObservedMS || (previous.EstimatedUTCMS == nil) != (frame.EstimatedUTCMS == nil) {
			continue
		}
		previousMS := effectiveFrameTime(previous)
		if previousMS > effectiveFrameTime(frame) {
			continue
		}
		var configID string
		if err := tx.QueryRowContext(ctx, `SELECT id FROM config_snapshots WHERE deployment_id=? AND host_id=? AND target_id=? AND config_hash=?`, batch.DeploymentID, batch.HostID, observation.TargetID, *observation.PreviousConfigHash).Scan(&configID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return configBoundary{}, false, nil
			}
			return configBoundary{}, false, err
		}
		return configBoundary{configID: configID, configHash: *observation.PreviousConfigHash, observedMS: previousMS}, true, nil
	}
	if err := rows.Err(); err != nil {
		return configBoundary{}, false, err
	}
	return configBoundary{}, false, nil
}

func (s *Store) verifiedCrossBootConfigPredecessor(ctx context.Context, tx *sql.Tx, batch protocol.CollectorBatch, frame protocol.CollectorFrame) (configBoundary, bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT original_collector_boot_id,payload,aligned_ms FROM source_frames WHERE deployment_id=? AND host_id=? AND source_id=? AND aligned_ms IS NOT NULL AND aligned_ms<? ORDER BY aligned_ms DESC,admitted_ms DESC LIMIT 32`, batch.DeploymentID, batch.HostID, frame.SourceID, *frame.EstimatedUTCMS)
	if err != nil {
		return configBoundary{}, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var bootID string
		var payload []byte
		var alignedMS int64
		if err := rows.Scan(&bootID, &payload, &alignedMS); err != nil {
			return configBoundary{}, false, err
		}
		if bootID == batch.CollectorBootID {
			continue
		}
		previous, err := s.codec.Decode(payload)
		if err != nil {
			return configBoundary{}, false, err
		}
		if previous.ConfigObservation == nil || previous.ConfigObservation.TargetID != frame.ConfigObservation.TargetID {
			continue
		}
		var configID string
		if err := tx.QueryRowContext(ctx, `SELECT id FROM config_snapshots WHERE deployment_id=? AND host_id=? AND target_id=? AND config_hash=?`, batch.DeploymentID, batch.HostID, frame.ConfigObservation.TargetID, previous.ConfigObservation.ConfigHash).Scan(&configID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return configBoundary{}, false, nil
			}
			return configBoundary{}, false, err
		}
		return configBoundary{configID: configID, configHash: previous.ConfigObservation.ConfigHash, observedMS: alignedMS}, true, nil
	}
	if err := rows.Err(); err != nil {
		return configBoundary{}, false, err
	}
	return configBoundary{}, false, nil
}

// persistProcessObservations keeps the bounded, privacy-reviewed identity
// needed to select a process after its raw frame has rolled up. It deliberately
// stores no PID, basename, executable path, arguments, or environment.
func persistProcessObservations(ctx context.Context, tx *sql.Tx, batch protocol.CollectorBatch, frame protocol.CollectorFrame, admittedMS int64) error {
	observedMS := frame.ObservedWallMS
	if frame.EstimatedUTCMS != nil {
		observedMS = *frame.EstimatedUTCMS
	}
	incarnationID, err := persistEndpointAssociation(ctx, tx, batch, frame, observedMS, admittedMS)
	if err != nil {
		return err
	}
	for _, process := range frame.ProcessObservations {
		provenance, err := json.Marshal(process.Provenance)
		if err != nil {
			return fmt.Errorf("encode process provenance: %w", err)
		}
		var footprint any
		if process.PhysicalFootprintBytes != nil {
			footprint = string(*process.PhysicalFootprintBytes)
		}
		var processIncarnation any
		if incarnationID != nil && frame.EndpointAssociation != nil && frame.EndpointAssociation.ProcessKey != nil && process.ProcessKey == *frame.EndpointAssociation.ProcessKey {
			processIncarnation = *incarnationID
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO process_observations(deployment_id,host_id,target_id,incarnation_id,source_id,process_key_sha256,observed_ms,cpu_busy_ratio,physical_footprint_bytes,association_quality,method_revision,provenance_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING`,
			batch.DeploymentID, batch.HostID, process.TargetID, processIncarnation, frame.SourceID, process.ProcessKey, observedMS, process.CPUBusyRatio, footprint, string(process.AssociationQuality), process.Provenance.MethodRevision, string(provenance))
		if err != nil {
			return fmt.Errorf("insert process observation: %w", err)
		}
	}
	return nil
}

type endpointUnavailableFields struct {
	AssociationState string `json:"association_state"`
	Reason           string `json:"reason"`
	SelectorSHA256   string `json:"selector_sha256"`
	ManifestSHA256   string `json:"manifest_sha256"`
}

type verifiedExitFields struct {
	PID                  int                  `json:"pid"`
	ProcessStartIdentity domain.Uint64Decimal `json:"process_start_identity"`
	ProcessKey           string               `json:"process_key"`
}

// persistEndpointAssociation admits only the exact selected-process tuple
// proven in this frame. Listener ownership on its own remains raw evidence and
// cannot create an incarnation or selected-process observation.
func persistEndpointAssociation(ctx context.Context, tx *sql.Tx, batch protocol.CollectorBatch, frame protocol.CollectorFrame, observedMS, admittedMS int64) (*string, error) {
	association := frame.EndpointAssociation
	if association == nil {
		return nil, nil
	}
	if association.Quality != domain.AssociationVerified {
		if batch.DeliveryMode == "current" {
			if err := persistEndpointUnavailable(ctx, tx, batch, *association, observedMS, admittedMS); err != nil {
				return nil, err
			}
		}
		if batch.DeliveryMode == "current" && association.VerifiedExit != nil {
			if err := persistVerifiedProcessExit(ctx, tx, batch, *association, observedMS, admittedMS); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}

	var display any
	for _, process := range frame.ProcessObservations {
		if association.ProcessKey != nil && process.ProcessKey == *association.ProcessKey {
			if process.DisplayBasename != nil {
				display = *process.DisplayBasename
			}
			break
		}
	}
	var incarnationID string
	err := tx.QueryRowContext(ctx, `SELECT id FROM incarnations WHERE deployment_id=? AND host_id=? AND target_id=? AND boot_id=? AND pid=? AND process_start_identity=? AND process_key_sha256=?`, batch.DeploymentID, batch.HostID, association.TargetID, batch.CollectorBootID, *association.PID, string(*association.ProcessStartIdentity), *association.ProcessKey).Scan(&incarnationID)
	if errors.Is(err, sql.ErrNoRows) {
		incarnationID, err = domain.NewUUID()
		if err != nil {
			return nil, err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO incarnations(id,deployment_id,host_id,target_id,boot_id,pid,process_start_identity,process_key_sha256,sanitized_basename,first_seen_ms,last_seen_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, incarnationID, batch.DeploymentID, batch.HostID, association.TargetID, batch.CollectorBootID, *association.PID, string(*association.ProcessStartIdentity), *association.ProcessKey, display, observedMS, observedMS)
		if err != nil {
			return nil, ErrOwnershipMismatch
		}
	} else if err != nil {
		return nil, err
	} else {
		result, err := tx.ExecContext(ctx, `UPDATE incarnations SET first_seen_ms=min(first_seen_ms,?),last_seen_ms=max(last_seen_ms,?) WHERE deployment_id=? AND host_id=? AND target_id=? AND id=?`, observedMS, observedMS, batch.DeploymentID, batch.HostID, association.TargetID, incarnationID)
		if err != nil {
			return nil, err
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return nil, ErrOwnershipMismatch
		}
	}
	evidence, err := json.Marshal(association)
	if err != nil {
		return nil, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO endpoint_associations(deployment_id,host_id,target_id,incarnation_id,checked_ms,endpoint_hash,local_network_evidence_json,state,reason,identity_revision) VALUES(?,?,?,?,?,?,?,'verified','listener_runtime_manifest_verified',?) ON CONFLICT DO NOTHING`, batch.DeploymentID, batch.HostID, association.TargetID, incarnationID, observedMS, association.EndpointHash, string(evidence), association.IdentityRevision)
	if err != nil {
		return nil, fmt.Errorf("insert endpoint association: %w", err)
	}
	if batch.DeliveryMode == "current" && association.VerifiedExit != nil {
		if err := persistVerifiedProcessExit(ctx, tx, batch, *association, observedMS, admittedMS); err != nil {
			return nil, err
		}
	}
	return &incarnationID, nil
}

func persistEndpointUnavailable(ctx context.Context, tx *sql.Tx, batch protocol.CollectorBatch, association domain.EndpointAssociation, observedMS, admittedMS int64) error {
	fields, err := json.Marshal(endpointUnavailableFields{AssociationState: string(association.Quality), Reason: string(*association.Reason), SelectorSHA256: association.SelectorSHA256, ManifestSHA256: association.ManifestSHA256})
	if err != nil {
		return err
	}
	provenance, err := json.Marshal(association.Provenance)
	if err != nil {
		return err
	}
	var eventID, previousFields string
	err = tx.QueryRowContext(ctx, `SELECT e.id,e.allowlisted_fields_json FROM events e WHERE e.deployment_id=? AND e.host_id=? AND e.target_id=? AND e.code='endpoint_association_unavailable' AND NOT EXISTS (SELECT 1 FROM endpoint_associations a WHERE a.deployment_id=e.deployment_id AND a.host_id=e.host_id AND a.target_id=e.target_id AND a.checked_ms>e.occurred_end_ms) ORDER BY e.detected_ms DESC LIMIT 1`, batch.DeploymentID, batch.HostID, association.TargetID).Scan(&eventID, &previousFields)
	if err == nil && previousFields == string(fields) {
		_, err = tx.ExecContext(ctx, `UPDATE events SET occurred_end_ms=?,detected_ms=?,repeat_count=repeat_count+1 WHERE deployment_id=? AND host_id=? AND id=? AND occurred_end_ms<=?`, observedMS, admittedMS, batch.DeploymentID, batch.HostID, eventID, observedMS)
		return err
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	eventID, err = domain.NewUUID()
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO events(id,deployment_id,host_id,target_id,incarnation_id,occurred_start_ms,occurred_end_ms,detected_ms,code,severity,allowlisted_fields_json,source,provenance_json,repeat_count) VALUES(?,?,?,?,NULL,?,?,?,'endpoint_association_unavailable','unknown',?,'collector',?,1)`, eventID, batch.DeploymentID, batch.HostID, association.TargetID, observedMS, observedMS, admittedMS, string(fields), string(provenance))
	return err
}

func persistVerifiedProcessExit(ctx context.Context, tx *sql.Tx, batch protocol.CollectorBatch, association domain.EndpointAssociation, observedMS, admittedMS int64) error {
	exit := association.VerifiedExit
	if exit == nil {
		return nil
	}
	var incarnationID string
	err := tx.QueryRowContext(ctx, `SELECT id FROM incarnations WHERE deployment_id=? AND host_id=? AND target_id=? AND boot_id=? AND pid=? AND process_start_identity=? AND process_key_sha256=?`, batch.DeploymentID, batch.HostID, association.TargetID, batch.CollectorBootID, exit.PID, string(exit.ProcessStartIdentity), exit.ProcessKey).Scan(&incarnationID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	fields, err := json.Marshal(verifiedExitFields{PID: exit.PID, ProcessStartIdentity: exit.ProcessStartIdentity, ProcessKey: exit.ProcessKey})
	if err != nil {
		return err
	}
	provenance, err := json.Marshal(association.Provenance)
	if err != nil {
		return err
	}
	eventID, err := domain.NewUUID()
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO events(id,deployment_id,host_id,target_id,incarnation_id,occurred_start_ms,occurred_end_ms,detected_ms,code,severity,allowlisted_fields_json,source,provenance_json,repeat_count) VALUES(?,?,?,?,?,?,?,?, 'selected_process_exit_verified','info',?,'collector',?,1)`, eventID, batch.DeploymentID, batch.HostID, association.TargetID, incarnationID, exit.LastSeenMS, observedMS, admittedMS, string(fields), string(provenance))
	return err
}

func (s *Store) IngestSourceStatus(ctx context.Context, status protocol.SourceStatus) (protocol.StatusACK, error) {
	if err := status.Validate(); err != nil {
		return protocol.StatusACK{}, err
	}
	payload, err := json.Marshal(status)
	if err != nil {
		return protocol.StatusACK{}, err
	}
	if len(payload) > int(protocol.MaxStatusBytes) {
		return protocol.StatusACK{}, errors.New("status payload exceeds control lane")
	}
	sum := sha256.Sum256(payload)
	hash := hex.EncodeToString(sum[:])
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return protocol.StatusACK{}, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return protocol.StatusACK{}, err
	}
	defer tx.Rollback()
	if _, err := validateCurrentSession(ctx, tx, status.DeploymentID, status.HostID, status.SecurityGeneration, status.SessionGeneration, status.CollectorBootID); err != nil {
		return protocol.StatusACK{}, err
	}
	now := s.clock.Now().UnixMilli()
	for _, source := range status.Sources {
		if err := requireSourceOwner(ctx, tx, status.DeploymentID, status.HostID, source.SourceID, true); err != nil {
			return protocol.StatusACK{}, err
		}
	}
	for _, loss := range status.LossIntervals {
		if err := requireSourceOwner(ctx, tx, status.DeploymentID, status.HostID, loss.SourceID, false); err != nil {
			return protocol.StatusACK{}, err
		}
	}
	var existing string
	err = tx.QueryRowContext(ctx, `SELECT payload_sha256 FROM source_status WHERE deployment_id=? AND host_id=? AND collector_boot_id=? AND sequence=?`, status.DeploymentID, status.HostID, status.CollectorBootID, status.Sequence).Scan(&existing)
	duplicate := false
	if err == nil {
		if existing != hash {
			return protocol.StatusACK{}, ErrOwnershipMismatch
		}
		duplicate = true
	} else if errors.Is(err, sql.ErrNoRows) {
		// Source status is the live control lane. Exact ACK-loss retries remain
		// idempotent at any age, while newly admitted heartbeats must be current.
		if status.ObservedWallMS < now-60000 {
			return protocol.StatusACK{}, ErrStatusObservationExpired
		}
		if status.ObservedWallMS > now+60000 {
			return protocol.StatusACK{}, ErrGenerationConflict
		}
		var latestSequence int64
		err := tx.QueryRowContext(ctx, `SELECT sequence FROM source_status WHERE deployment_id=? AND host_id=? AND collector_boot_id=? ORDER BY sequence DESC LIMIT 1`, status.DeploymentID, status.HostID, status.CollectorBootID).Scan(&latestSequence)
		if err == nil && status.Sequence <= latestSequence {
			return protocol.StatusACK{}, ErrGenerationConflict
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return protocol.StatusACK{}, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO source_status(deployment_id,host_id,security_generation,session_generation,collector_boot_id,sequence,observed_ms,payload_json,payload_sha256,admitted_ms) VALUES(?,?,?,?,?,?,?,?,?,?)`, status.DeploymentID, status.HostID, status.SecurityGeneration, status.SessionGeneration, status.CollectorBootID, status.Sequence, status.ObservedWallMS, string(payload), hash, now); err != nil {
			return protocol.StatusACK{}, err
		}
	} else {
		return protocol.StatusACK{}, err
	}
	if err := tx.Commit(); err != nil {
		return protocol.StatusACK{}, err
	}
	return protocol.StatusACK{CollectorBootID: status.CollectorBootID, Sequence: status.Sequence, Durable: true, Duplicate: duplicate, HubTimeMS: now, ControlRequests: []protocol.ControlRequest{}}, nil
}

func validateBatchSession(ctx context.Context, tx *sql.Tx, batch protocol.CollectorBatch) error {
	var recovery, generation string
	var current int64
	var boot sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT d.recovery_state,d.deployment_generation,h.current_session_generation,h.last_boot_id FROM deployments d JOIN hosts h ON h.deployment_id=d.id WHERE d.id=? AND h.id=? AND h.retired_ms IS NULL`, batch.DeploymentID, batch.HostID).Scan(&recovery, &generation, &current, &boot)
	if err != nil {
		return ownershipError(err)
	}
	if recovery != "normal" || generation != batch.SecurityGeneration {
		return ErrAdmissionFenced
	}
	var superseded sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT superseded_ms FROM collector_sessions WHERE deployment_id=? AND host_id=? AND security_generation=? AND session_generation=? AND collector_boot_id=?`, batch.DeploymentID, batch.HostID, batch.SecurityGeneration, batch.SessionGeneration, batch.CollectorBootID).Scan(&superseded); err != nil {
		return ErrGenerationConflict
	}
	if batch.DeliveryMode == "current" && (current != batch.SessionGeneration || !boot.Valid || boot.String != batch.CollectorBootID || superseded.Valid) {
		return ErrGenerationConflict
	}
	return nil
}

func validateFrameOwnership(ctx context.Context, tx *sql.Tx, batch protocol.CollectorBatch, frame protocol.CollectorFrame) error {
	var kind string
	var target sql.NullString
	var retired sql.NullInt64
	err := tx.QueryRowContext(ctx, `SELECT kind,target_id,retired_ms FROM sources WHERE deployment_id=? AND host_id=? AND id=?`, batch.DeploymentID, batch.HostID, frame.SourceID).Scan(&kind, &target, &retired)
	if err != nil {
		return ownershipError(err)
	}
	if batch.DeliveryMode == "current" && retired.Valid {
		return ErrOwnershipMismatch
	}
	hostGauge, runtimeGauge := false, false
	for id := range frame.Gauges {
		if id == "runtime.reachable" {
			runtimeGauge = true
		} else {
			hostGauge = true
		}
	}
	switch kind {
	case "host":
		if runtimeGauge || len(frame.ModelObservations) > 0 || frame.ConfigObservation != nil {
			return ErrOwnershipMismatch
		}
	case "runtime":
		if hostGauge || len(frame.NetworkObservations) > 0 || len(frame.ProcessObservations) > 0 || frame.ProcessSummary != nil || frame.EndpointAssociation != nil {
			return ErrOwnershipMismatch
		}
	default:
		return ErrOwnershipMismatch
	}
	if frame.ConfigObservation != nil && (!target.Valid || frame.ConfigObservation.TargetID != target.String) {
		return ErrOwnershipMismatch
	}
	if frame.EndpointAssociation != nil {
		association := frame.EndpointAssociation
		var selector string
		if err := tx.QueryRowContext(ctx, `SELECT local_selector_hash FROM targets WHERE deployment_id=? AND host_id=? AND id=?`, batch.DeploymentID, batch.HostID, association.TargetID).Scan(&selector); err != nil || selector != association.SelectorSHA256 || selector != association.EndpointHash {
			return ErrOwnershipMismatch
		}
		if association.Quality == domain.AssociationVerified {
			matched := false
			for _, process := range frame.ProcessObservations {
				if process.TargetID != nil && *process.TargetID == association.TargetID && association.ProcessKey != nil && process.ProcessKey == *association.ProcessKey && association.PID != nil && process.PID == *association.PID && association.ProcessStartIdentity != nil && process.ProcessStartIdentity == *association.ProcessStartIdentity && process.AssociationQuality == domain.AssociationVerified {
					matched = true
					break
				}
			}
			if !matched {
				return ErrOwnershipMismatch
			}
		}
	}
	if frame.IncarnationID != nil {
		if !target.Valid {
			return ErrOwnershipMismatch
		}
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM incarnations WHERE deployment_id=? AND host_id=? AND target_id=? AND id=?`, batch.DeploymentID, batch.HostID, target.String, *frame.IncarnationID).Scan(&count); err != nil || count != 1 {
			return ErrOwnershipMismatch
		}
	}
	for _, model := range frame.ModelObservations {
		if !target.Valid {
			return ErrOwnershipMismatch
		}
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM model_revisions WHERE deployment_id=? AND host_id=? AND target_id=? AND id=? AND digest=?`, batch.DeploymentID, batch.HostID, target.String, model.ModelID, model.Digest).Scan(&count); err != nil || count != 1 {
			return ErrOwnershipMismatch
		}
	}
	for _, process := range frame.ProcessObservations {
		if process.HostID != batch.HostID {
			return ErrOwnershipMismatch
		}
		if process.TargetID != nil {
			var count int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM targets WHERE deployment_id=? AND host_id=? AND id=?`, batch.DeploymentID, batch.HostID, *process.TargetID).Scan(&count); err != nil || count != 1 {
				return ErrOwnershipMismatch
			}
		}
	}
	return nil
}

func (s *Store) validateCurrentFrameOrder(ctx context.Context, tx *sql.Tx, batch protocol.CollectorBatch, frame protocol.CollectorFrame, now int64) error {
	// Late observations remain useful history. Only an aligned timestamp beyond
	// the future-tolerance boundary is invalid at admission.
	if frame.EstimatedUTCMS != nil && *frame.EstimatedUTCMS > now+60000 {
		return ErrGenerationConflict
	}
	var sequence int64
	var payload []byte
	err := tx.QueryRowContext(ctx, `SELECT sequence,payload FROM source_frames WHERE deployment_id=? AND host_id=? AND session_generation=? AND collector_boot_id=? AND source_id=? AND delivery_mode='current' ORDER BY sequence DESC LIMIT 1`, batch.DeploymentID, batch.HostID, batch.SessionGeneration, batch.CollectorBootID, frame.SourceID).Scan(&sequence, &payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if frame.Sequence <= sequence {
		return ErrGenerationConflict
	}
	previous, err := s.codec.Decode(payload)
	if err != nil {
		return err
	}
	previousStart, err := parseStoredDecimal(previous.MonotonicStartNS)
	if err != nil {
		return err
	}
	currentStart, err := parseStoredDecimal(frame.MonotonicStartNS)
	if err != nil || currentStart < previousStart {
		return ErrGenerationConflict
	}
	return nil
}

func parseStoredDecimal(value domain.Uint64Decimal) (uint64, error) {
	return strconv.ParseUint(string(value), 10, 64)
}

func requireSourceOwner(ctx context.Context, tx *sql.Tx, deploymentID, hostID, sourceID string, active bool) error {
	query := `SELECT count(*) FROM sources WHERE deployment_id=? AND host_id=? AND id=?`
	if active {
		query += ` AND retired_ms IS NULL`
	}
	var count int
	if err := tx.QueryRowContext(ctx, query, deploymentID, hostID, sourceID).Scan(&count); err != nil || count != 1 {
		return ErrOwnershipMismatch
	}
	return nil
}
