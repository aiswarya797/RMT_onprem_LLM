package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"

	"rmt.local/monitor/internal/alerts"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
)

const (
	alertCursorKey                            = "alerts_v1"
	alertDestinationLimit                     = 16
	alertCapsuleSourceLimit                   = 16
	alertCapsuleGapLimit                      = 16
	alertCapsuleReasonLimit                   = 16
	alertCapsuleConfigIDLimit                 = 16
	alertCapsulePayloadLimit                  = 64 << 10
	alertNotificationPayloadMax               = 64 << 10
	alertFiringIncidentReservationBytes int64 = 69632
	alertCursorIncidentReservationBytes int64 = 4096
	alertCursorMetadataReservationBytes int64 = 24576
	alertCursorLiveReservationBytes     int64 = 28672
)

var (
	ErrAlertInvalid              = errors.New("invalid alert evaluation")
	ErrAlertRuleDisabled         = errors.New("alert rule disabled")
	ErrAlertCursorConflict       = errors.New("alert evaluator cursor conflict")
	ErrAlertCapacityUncalibrated = errors.New("alert capacity envelope is not calibrated")
	ErrAlertCapacity             = errors.New("alert durable capacity exhausted")
	ErrAlertDestinationLimit     = errors.New("alert destination limit exceeded")
)

type AlertInputCursor struct {
	InputOrdinal      int64  `json:"input_ordinal"`
	ObservedThroughMS int64  `json:"observed_through_ms"`
	InputSHA256       string `json:"input_sha256"`
}

type AlertEvaluationWrite struct {
	DeploymentID         string
	DeploymentGeneration string
	RuleID               string
	RuleVersion          int64
	Cursor               AlertInputCursor
	EventMS              int64
	ElapsedMS            int64
	HubRestarted         bool
	// CurrentLive is set only for the current admitted session/generation.
	// Historical and restored_replay inputs remain queryable but may not
	// advance alert state or produce notification intents.
	CurrentLive     bool
	Input           alerts.Input
	ObservedDwellMS int64
	Evidence        *AlertCapsuleEvidence
	Fence           AlertEvaluationFence
	Episode         *AlertReachabilityEpisodeWrite
}

type AlertCapsuleEvidence struct {
	MetricID                string              `json:"metric_id"`
	Unit                    string              `json:"unit"`
	WindowStartMS           int64               `json:"window_start_ms"`
	WindowEndMS             int64               `json:"window_end_ms"`
	ObservedMS              int64               `json:"observed_ms"`
	Quality                 string              `json:"quality"`
	NumberValue             *float64            `json:"number_value"`
	StateValue              *string             `json:"state_value"`
	BooleanValue            *bool               `json:"boolean_value"`
	ValidN                  *int                `json:"valid_n"`
	CompletedN              *int                `json:"completed_n"`
	SourceSamples           []AlertSourceSample `json:"source_samples"`
	SourceSampleCount       int                 `json:"source_sample_count"`
	SourceSamplesTruncated  bool                `json:"source_samples_truncated"`
	RequestSampleIDs        []string            `json:"request_sample_ids"`
	RequestSampleCount      int                 `json:"request_sample_count"`
	RequestSamplesTruncated bool                `json:"request_samples_truncated"`
	StatusSample            *AlertStatusSample  `json:"status_sample,omitempty"`
	StatusAbsence           *AlertStatusAbsence `json:"status_absence,omitempty"`
	DefinitionRevision      string              `json:"definition_revision"`
	MethodRevision          string              `json:"method_revision"`
	Gaps                    []AlertEvidenceGap  `json:"gaps"`
	UnavailableReasons      []string            `json:"unavailable_reasons"`
}

type AlertStatusSample struct {
	HostID            string `json:"host_id"`
	CollectorBootID   string `json:"collector_boot_id"`
	SessionGeneration int64  `json:"session_generation"`
	Sequence          int64  `json:"sequence"`
	PayloadSHA256     string `json:"payload_sha256"`
	ObservedMS        int64  `json:"observed_ms"`
	AdmittedMS        int64  `json:"admitted_ms"`
}

type AlertStatusAbsence struct {
	HostID            string  `json:"host_id"`
	CollectorBootID   *string `json:"collector_boot_id"`
	SessionGeneration int64   `json:"session_generation"`
	CheckedMS         int64   `json:"checked_ms"`
}

type AlertSourceSample struct {
	CollectorBootID string   `json:"collector_boot_id"`
	SourceID        string   `json:"source_id"`
	Sequence        int64    `json:"sequence"`
	ConfigIDs       []string `json:"config_ids"`
}

type AlertEvidenceGap struct {
	StartMS int64  `json:"start_ms"`
	EndMS   int64  `json:"end_ms"`
	Reason  string `json:"reason"`
}

type alertIncidentScope struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

type AlertEvaluationResult struct {
	InstanceID    string             `json:"instance_id"`
	IncidentID    *string            `json:"incident_id"`
	Snapshot      alerts.Snapshot    `json:"snapshot"`
	Transition    *alerts.Transition `json:"transition"`
	OutboxIntents int                `json:"outbox_intents"`
	Duplicate     bool               `json:"duplicate"`
}

type persistedAlertCursor struct {
	RuleVersion       int64  `json:"rule_version"`
	ScopeFingerprint  string `json:"scope_fingerprint"`
	InputOrdinal      int64  `json:"input_ordinal"`
	ObservedThroughMS int64  `json:"observed_through_ms"`
	InputSHA256       string `json:"input_sha256"`
	InstanceID        string `json:"instance_id"`
	TransitionSeq     int64  `json:"transition_seq"`
	TransitionWritten bool   `json:"transition_written"`
}

type AlertTriggerCapsule struct {
	SchemaRevision string                 `json:"schema_revision"`
	CardRevision   string                 `json:"card_revision"`
	IncidentID     string                 `json:"incident_id"`
	InstanceID     string                 `json:"instance_id"`
	Rule           AlertCapsuleRule       `json:"rule"`
	Evaluation     AlertCapsuleEvaluation `json:"evaluation"`
	Evidence       AlertCapsuleEvidence   `json:"evidence"`
}

type AlertCapsuleRule struct {
	ID                string                   `json:"id"`
	Version           int64                    `json:"version"`
	EvaluatorType     alerts.RuleType          `json:"evaluator_type"`
	ScopeID           string                   `json:"scope_id"`
	ScopeFingerprint  string                   `json:"scope_fingerprint"`
	IncarnationPolicy alerts.IncarnationPolicy `json:"incarnation_policy"`
}

type AlertCapsuleEvaluation struct {
	EventMS         int64            `json:"event_ms"`
	InputOrdinal    int64            `json:"input_cursor_ordinal"`
	InputSHA256     string           `json:"input_sha256"`
	PreviousState   alerts.State     `json:"previous_state"`
	NewState        alerts.State     `json:"new_state"`
	DataState       alerts.DataState `json:"data_state"`
	Predicate       alerts.Predicate `json:"predicate"`
	Reason          string           `json:"reason"`
	ObservedDwellMS int64            `json:"observed_dwell_ms"`
	EvidenceSHA256  string           `json:"evidence_sha256"`
}

// ApplyAlertEvaluation is the durable alert boundary. It intentionally has no
// HTTP/session actor: the hub evaluator supplies a current deployment
// generation and a frozen input cursor. Administrative rule changes use the
// actor-revalidated APIs in alerts_rules.go.
func (s *Store) ApplyAlertEvaluation(ctx context.Context, write AlertEvaluationWrite) (AlertEvaluationResult, error) {
	if err := validateAlertWrite(write); err != nil {
		return AlertEvaluationResult{}, err
	}
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return AlertEvaluationResult{}, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AlertEvaluationResult{}, err
	}
	defer tx.Rollback()
	if err := validateAlertGenerationTx(ctx, tx, write); err != nil {
		return AlertEvaluationResult{}, err
	}
	record, err := readRuleTx(ctx, tx, write.DeploymentID, write.RuleID)
	if err != nil {
		return AlertEvaluationResult{}, err
	}
	if !record.Definition.Enabled {
		return AlertEvaluationResult{}, ErrAlertRuleDisabled
	}
	if record.Revision != write.RuleVersion {
		return AlertEvaluationResult{}, ErrRuleRevision
	}
	capacityNowMS := s.clock.Now().UnixMilli()
	scope, _, spec, err := validateRuleDefinition(record.Definition)
	if err != nil {
		return AlertEvaluationResult{}, err
	}
	spec.RuleID, spec.Version = record.ID, record.Revision
	spec.ScopeFingerprint, err = canonicalRuleScopeFingerprint(scope)
	if err != nil {
		return AlertEvaluationResult{}, err
	}
	decision, err := alerts.Evaluate(spec, write.Input)
	if err != nil {
		return AlertEvaluationResult{}, ErrAlertInvalid
	}
	cursors, err := readAlertCursorsTx(ctx, tx, write.DeploymentID)
	if err != nil {
		return AlertEvaluationResult{}, err
	}
	if prior, ok := cursors[write.RuleID]; ok {
		if prior.RuleVersion == write.RuleVersion && prior.ScopeFingerprint == spec.ScopeFingerprint && prior.InputOrdinal == write.Cursor.InputOrdinal {
			if prior.InputSHA256 != write.Cursor.InputSHA256 || prior.ObservedThroughMS != write.Cursor.ObservedThroughMS {
				return AlertEvaluationResult{}, ErrAlertCursorConflict
			}
			result, err := readAlertEvaluationResultTx(ctx, tx, write.DeploymentID, prior.InstanceID, prior.TransitionSeq, prior.TransitionWritten)
			if err != nil {
				return AlertEvaluationResult{}, err
			}
			result.Duplicate = true
			if err := tx.Commit(); err != nil {
				return AlertEvaluationResult{}, err
			}
			return result, nil
		}
		if prior.RuleVersion > write.RuleVersion || prior.RuleVersion == write.RuleVersion && prior.InputOrdinal >= write.Cursor.InputOrdinal {
			return AlertEvaluationResult{}, ErrAlertCursorConflict
		}
	}
	if err := validateAlertEvaluationFenceTx(ctx, tx, write.DeploymentID, scope, record.Definition, write.Fence); err != nil {
		return AlertEvaluationResult{}, err
	}
	if record.Definition.EvaluatorType == alerts.RuleOllamaUnreachable {
		if write.Episode != nil {
			_, err = applyAlertEpisodeTx(ctx, tx, write.DeploymentID, write)
		} else {
			err = validateAlertEpisodeObservationTx(ctx, tx, write.DeploymentID, write)
		}
		if err != nil {
			return AlertEvaluationResult{}, err
		}
	} else if write.Episode != nil {
		return AlertEvaluationResult{}, ErrAlertInvalid
	}
	instanceID, current, isNew, err := loadAlertSnapshotTx(ctx, tx, spec, write.DeploymentID)
	if err != nil {
		return AlertEvaluationResult{}, err
	}
	evaluation := alerts.Evaluation{EventMS: write.EventMS, ElapsedMS: write.ElapsedMS, HubRestarted: write.HubRestarted, Decision: decision, EvidenceHash: write.Cursor.InputSHA256}
	reduced, err := alerts.Reduce(spec, current, evaluation)
	if err != nil {
		return AlertEvaluationResult{}, err
	}
	envelope := alertEnvelopeCursor
	if reduced.Transition != nil {
		envelope = alertEnvelopeTransition
		if reduced.Transition.NewState == alerts.StateFiring && current.State != alerts.StateRecovering {
			envelope = alertEnvelopeFiring
		} else if reduced.Transition.NewState == alerts.StateResolved {
			envelope = alertEnvelopeResolution
		}
	}
	if err := admitAlertEnvelopeTx(ctx, tx, write.DeploymentID, envelope, capacityNowMS); err != nil {
		return AlertEvaluationResult{}, err
	}
	if err := persistAlertSnapshotTx(ctx, tx, write.DeploymentID, instanceID, current, reduced.Snapshot, isNew); err != nil {
		return AlertEvaluationResult{}, err
	}
	if reduced.Transition != nil {
		if _, err := tx.ExecContext(ctx, `INSERT INTO alert_transitions(deployment_id,instance_id,transition_seq,previous_state,new_state,event_ms,evidence_hash) VALUES(?,?,?,?,?,?,?)`, write.DeploymentID, instanceID, reduced.Transition.Sequence, reduced.Transition.PreviousState, reduced.Transition.NewState, reduced.Transition.EventMS, reduced.Transition.EvidenceHash); err != nil {
			return AlertEvaluationResult{}, err
		}
	}
	result := AlertEvaluationResult{InstanceID: instanceID, Snapshot: reduced.Snapshot, Transition: reduced.Transition}
	if envelope == alertEnvelopeFiring {
		incidentID, intents, err := createAlertIncidentTx(ctx, tx, record, scope, spec, write, instanceID, decision, current, reduced)
		if err != nil {
			return AlertEvaluationResult{}, err
		}
		result.IncidentID, result.OutboxIntents = &incidentID, intents
	} else if envelope == alertEnvelopeResolution {
		incidentID, intents, err := resolveAlertIncidentTx(ctx, tx, record, write, instanceID, reduced)
		if err != nil {
			return AlertEvaluationResult{}, err
		}
		result.IncidentID, result.OutboxIntents = &incidentID, intents
	} else {
		result.IncidentID, err = readAlertIncidentIDTx(ctx, tx, write.DeploymentID, instanceID)
		if err != nil {
			return AlertEvaluationResult{}, err
		}
	}
	cursors[write.RuleID] = persistedAlertCursor{RuleVersion: write.RuleVersion, ScopeFingerprint: spec.ScopeFingerprint, InputOrdinal: write.Cursor.InputOrdinal, ObservedThroughMS: write.Cursor.ObservedThroughMS, InputSHA256: write.Cursor.InputSHA256, InstanceID: instanceID, TransitionSeq: reduced.Snapshot.TransitionSeq, TransitionWritten: reduced.Transition != nil}
	if err := writeAlertCursorsTx(ctx, tx, write.DeploymentID, cursors, capacityNowMS); err != nil {
		return AlertEvaluationResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return AlertEvaluationResult{}, err
	}
	return result, nil
}

type alertEnvelope int

const (
	alertEnvelopeCursor alertEnvelope = iota
	alertEnvelopeTransition
	alertEnvelopeFiring
	alertEnvelopeResolution
)

// These page-rounded envelopes are pinned to the SQLite 3.53.4 dbstat
// witnesses in alert_capacity_calibration.json. The cursor witness measured
// the initial 64-rule snapshot and every following single-rule commit. Larger
// firing/resolution envelopes add that independent cursor peak to the table
// population measurement instead of relying on its lower bulk average.
func alertEnvelopeReservation(envelope alertEnvelope) (incidentBytes, metadataBytes, liveBytes int64, calibrated bool) {
	switch envelope {
	case alertEnvelopeCursor:
		return alertCursorIncidentReservationBytes, alertCursorMetadataReservationBytes, alertCursorLiveReservationBytes, true
	case alertEnvelopeTransition:
		return 4096, alertCursorMetadataReservationBytes, alertCursorLiveReservationBytes, true
	case alertEnvelopeFiring:
		return alertFiringIncidentReservationBytes, 1064960 + alertCursorMetadataReservationBytes, 1179648 + alertCursorMetadataReservationBytes, true
	case alertEnvelopeResolution:
		return 4096, 1064960 + alertCursorMetadataReservationBytes, 1069056 + alertCursorMetadataReservationBytes, true
	default:
		return 0, 0, 0, false
	}
}

func admitAlertEnvelopeTx(ctx context.Context, tx *sql.Tx, deploymentID string, envelope alertEnvelope, now int64) error {
	incidentBytes, metadataBytes, liveBytes, calibrated := alertEnvelopeReservation(envelope)
	if !calibrated {
		return ErrAlertCapacityUncalibrated
	}
	if incidentBytes < 0 || metadataBytes < 0 || liveBytes < 0 {
		return ErrAlertCapacity
	}
	var storageState, cursorJSON string
	if err := tx.QueryRowContext(ctx, `SELECT storage_state,evaluator_cursor_json FROM maintenance WHERE deployment_id=?`, deploymentID).Scan(&storageState, &cursorJSON); err != nil {
		return ErrAlertCapacity
	}
	if storageState == StorageReadOnlyENOSPC {
		return ErrAlertCapacity
	}
	observedMS, _, pendingBulk, err := readCapacityCursor(cursorJSON)
	if err != nil || observedMS > now+5000 || now-observedMS > CapacityMeasurementMaxAge.Milliseconds() {
		return ErrAlertCapacity
	}
	pendingRecovery, err := readPendingRecoveryCapacity(cursorJSON)
	if err != nil {
		return ErrAlertCapacity
	}
	pendingIncident, pendingMetadata, pendingLive, err := readPendingAlertCapacity(cursorJSON)
	if err != nil {
		return ErrAlertCapacity
	}
	if incidentBytes > math.MaxInt64-pendingIncident || metadataBytes > math.MaxInt64-pendingMetadata || liveBytes > math.MaxInt64-pendingLive {
		return ErrAlertCapacity
	}
	requests := map[string]int64{"incident_ledger": incidentBytes, "metadata": metadataBytes, "live_total": liveBytes}
	for class, requested := range requests {
		var limit, current, reserved int64
		if err := tx.QueryRowContext(ctx, `SELECT byte_limit,current_physical_bytes,reserved_physical_bytes FROM quota_classes WHERE deployment_id=? AND class=?`, deploymentID, class).Scan(&limit, &current, &reserved); err != nil {
			return ErrAlertCapacity
		}
		pending := int64(0)
		switch class {
		case "incident_ledger":
			pending = pendingIncident
		case "metadata":
			if pendingRecovery > math.MaxInt64-pendingMetadata {
				return ErrAlertCapacity
			}
			pending = pendingMetadata + pendingRecovery
		case "live_total":
			values := []int64{pendingBulk, pendingRecovery, pendingLive}
			for _, value := range values {
				if value > math.MaxInt64-pending {
					return ErrAlertCapacity
				}
				pending += value
			}
		}
		if requested > limit || current > math.MaxInt64-reserved || current+reserved > math.MaxInt64-pending || current+reserved+pending > limit-requested {
			return ErrAlertCapacity
		}
	}
	return writePendingAlertCapacity(ctx, tx, deploymentID, pendingIncident+incidentBytes, pendingMetadata+metadataBytes, pendingLive+liveBytes)
}

func validateAlertWrite(write AlertEvaluationWrite) error {
	if !write.CurrentLive || !validUUIDText(write.DeploymentID) || !validUUIDText(write.DeploymentGeneration) || !validUUIDText(write.RuleID) || write.RuleVersion < 1 || write.Cursor.InputOrdinal < 1 || write.Cursor.ObservedThroughMS < 0 || !sha256HexPattern.MatchString(write.Cursor.InputSHA256) || write.EventMS < 0 || write.ElapsedMS < 0 || write.ObservedDwellMS < 0 {
		return ErrAlertInvalid
	}
	return nil
}

func validateAlertGenerationTx(ctx context.Context, tx *sql.Tx, write AlertEvaluationWrite) error {
	var generation, recovery string
	if err := tx.QueryRowContext(ctx, `SELECT deployment_generation,recovery_state FROM deployments WHERE id=?`, write.DeploymentID).Scan(&generation, &recovery); err != nil {
		return ErrAdmissionFenced
	}
	if generation != write.DeploymentGeneration || recovery != "normal" {
		return ErrAdmissionFenced
	}
	return nil
}

func loadAlertSnapshotTx(ctx context.Context, tx *sql.Tx, spec alerts.Spec, deploymentID string) (string, alerts.Snapshot, bool, error) {
	var instanceID string
	var value alerts.Snapshot
	var lastValid, opened, resolved, acknowledgedMS, muted sql.NullInt64
	var acknowledgedBy sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT id,active_generation,state,data_state,dwell_ms,last_eval_ms,last_valid_ms,opened_ms,resolved_ms,acknowledged_by,acknowledged_ms,muted_until_ms,transition_seq FROM alert_instances WHERE deployment_id=? AND rule_id=? AND rule_version=? AND scope_fingerprint=? ORDER BY active_generation DESC LIMIT 1`, deploymentID, spec.RuleID, spec.Version, spec.ScopeFingerprint).Scan(&instanceID, &value.ActiveGeneration, &value.State, &value.DataState, &value.DwellMS, &value.LastEvalMS, &lastValid, &opened, &resolved, &acknowledgedBy, &acknowledgedMS, &muted, &value.TransitionSeq)
	if errors.Is(err, sql.ErrNoRows) {
		value, err = alerts.NewSnapshot(spec, 1)
		if err != nil {
			return "", alerts.Snapshot{}, false, err
		}
		instanceID, err = domain.NewUUID()
		return instanceID, value, true, err
	}
	if err != nil {
		return "", alerts.Snapshot{}, false, err
	}
	value.RuleID, value.RuleVersion, value.ScopeFingerprint, value.IncarnationPolicy = spec.RuleID, spec.Version, spec.ScopeFingerprint, spec.IncarnationPolicy
	value.LastValidMS, value.OpenedMS, value.ResolvedMS = nullableInt64Pointer(lastValid), nullableInt64Pointer(opened), nullableInt64Pointer(resolved)
	value.AcknowledgedBy, value.AcknowledgedMS, value.MutedUntilMS = nullableStringPointer(acknowledgedBy), nullableInt64Pointer(acknowledgedMS), nullableInt64Pointer(muted)
	if value.State == alerts.StateResolved || value.State == alerts.StateSuperseded {
		generation := value.ActiveGeneration + 1
		value, err = alerts.NewSnapshot(spec, generation)
		if err != nil {
			return "", alerts.Snapshot{}, false, err
		}
		instanceID, err = domain.NewUUID()
		return instanceID, value, true, err
	}
	return instanceID, value, false, nil
}

func persistAlertSnapshotTx(ctx context.Context, tx *sql.Tx, deploymentID, instanceID string, previous, next alerts.Snapshot, isNew bool) error {
	if isNew {
		_, err := tx.ExecContext(ctx, `INSERT INTO alert_instances(id,deployment_id,rule_id,rule_version,scope_fingerprint,active_generation,state,data_state,dwell_ms,last_eval_ms,last_valid_ms,opened_ms,resolved_ms,acknowledged_by,acknowledged_ms,muted_until_ms,transition_seq) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, instanceID, deploymentID, next.RuleID, next.RuleVersion, next.ScopeFingerprint, next.ActiveGeneration, next.State, next.DataState, next.DwellMS, next.LastEvalMS, next.LastValidMS, next.OpenedMS, next.ResolvedMS, next.AcknowledgedBy, next.AcknowledgedMS, next.MutedUntilMS, next.TransitionSeq)
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE alert_instances SET state=?,data_state=?,dwell_ms=?,last_eval_ms=?,last_valid_ms=?,opened_ms=?,resolved_ms=?,acknowledged_by=?,acknowledged_ms=?,muted_until_ms=?,transition_seq=? WHERE deployment_id=? AND id=? AND rule_version=? AND active_generation=? AND transition_seq=?`, next.State, next.DataState, next.DwellMS, next.LastEvalMS, next.LastValidMS, next.OpenedMS, next.ResolvedMS, next.AcknowledgedBy, next.AcknowledgedMS, next.MutedUntilMS, next.TransitionSeq, deploymentID, instanceID, previous.RuleVersion, previous.ActiveGeneration, previous.TransitionSeq)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrAlertCursorConflict
	}
	return nil
}

func createAlertIncidentTx(ctx context.Context, tx *sql.Tx, record RuleRecord, scope ruleScope, spec alerts.Spec, write AlertEvaluationWrite, instanceID string, decision alerts.Decision, previous alerts.Snapshot, reduced alerts.Result) (string, int, error) {
	if write.Evidence == nil || reduced.Transition == nil {
		return "", 0, ErrAlertInvalid
	}
	evidence := normalizeAlertCapsuleEvidence(*write.Evidence)
	if err := validateAlertCapsuleEvidence(record.Definition, write.Input, evidence); err != nil {
		return "", 0, err
	}
	if err := validateAlertStatusEvidenceFence(write.Fence, evidence); err != nil {
		return "", 0, err
	}
	if err := validateAlertEvidenceReferencesTx(ctx, tx, write.DeploymentID, record.Definition, evidence); err != nil {
		return "", 0, err
	}
	if reduced.Transition.NewState != alerts.StateFiring || decision.Predicate != alerts.PredicateMatch || !decision.Evaluable {
		return "", 0, ErrAlertInvalid
	}
	if !decision.Immediate && write.ObservedDwellMS < spec.TriggerDwellMS {
		return "", 0, ErrAlertInvalid
	}
	incidentID, err := domain.NewUUID()
	if err != nil {
		return "", 0, err
	}
	if !validObservedDwell(spec, write, previous, decision) {
		return "", 0, ErrAlertInvalid
	}
	capsule := AlertTriggerCapsule{SchemaRevision: "alert-trigger-capsule-1", CardRevision: "ec01-ec07-mac-1", IncidentID: incidentID, InstanceID: instanceID, Rule: AlertCapsuleRule{ID: record.ID, Version: record.Revision, EvaluatorType: record.Definition.EvaluatorType, ScopeID: scope.ScopeID, ScopeFingerprint: spec.ScopeFingerprint, IncarnationPolicy: spec.IncarnationPolicy}, Evaluation: AlertCapsuleEvaluation{EventMS: write.EventMS, InputOrdinal: write.Cursor.InputOrdinal, InputSHA256: write.Cursor.InputSHA256, PreviousState: previous.State, NewState: reduced.Snapshot.State, DataState: reduced.Snapshot.DataState, Predicate: decision.Predicate, Reason: decision.Reason, ObservedDwellMS: write.ObservedDwellMS, EvidenceSHA256: write.Cursor.InputSHA256}, Evidence: evidence}
	encoded, err := json.Marshal(capsule)
	if err != nil || len(encoded) > alertCapsulePayloadLimit {
		return "", 0, ErrAlertInvalid
	}
	payloadHash := sha256.Sum256(encoded)
	payloadSHA256 := hex.EncodeToString(payloadHash[:])
	incidentScopeKind := scope.ScopeKind
	if incidentScopeKind == "target" {
		incidentScopeKind = "runtime"
	}
	scopeJSON, _ := json.Marshal(alertIncidentScope{Kind: incidentScopeKind, ID: scope.ScopeID})
	title := "Alert: " + strings.ReplaceAll(string(record.Definition.EvaluatorType), "_", " ")
	if _, err := tx.ExecContext(ctx, `INSERT INTO incidents(id,deployment_id,target_scope_json,title,origin,start_ms,end_ms,alert_instance_id,workflow_state,owner_user_id,snapshot_id,evidence_expiry_reason,version,created_ms,updated_ms) VALUES(?,?,?,?, 'alert',?,NULL,?,'open',NULL,NULL,NULL,1,?,?)`, incidentID, write.DeploymentID, string(scopeJSON), title, write.EventMS, instanceID, write.EventMS, write.EventMS); err != nil {
		if strings.Contains(err.Error(), "open_incident_cap_1000") {
			return "", 0, ErrIncidentLimit
		}
		return "", 0, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO incident_capsules(deployment_id,incident_id,schema_revision,card_revision,rule_revision,payload,payload_sha256,physical_reservation_bytes,evidence_state,expires_ms,resolved_ms) VALUES(?,?, 'alert-trigger-capsule-1','ec01-ec07-mac-1',?,?,?,?, 'complete',NULL,NULL)`, write.DeploymentID, incidentID, record.Revision, encoded, payloadSHA256, incidentCapsulePayloadReservationBytes); err != nil {
		return "", 0, err
	}
	intents, err := createAlertOutboxTx(ctx, tx, write.DeploymentID, record, instanceID, incidentID, reduced.Transition.Sequence, reduced.Snapshot.ActiveGeneration, reduced.Snapshot.State, reduced.Snapshot.DataState, write.EventMS, write.Cursor.InputSHA256, reduced.Snapshot.MutedUntilMS)
	if err != nil {
		return "", 0, err
	}
	return incidentID, intents, nil
}

func validObservedDwell(spec alerts.Spec, write AlertEvaluationWrite, previous alerts.Snapshot, decision alerts.Decision) bool {
	if spec.Type == alerts.RuleHostNotReporting {
		return write.Input.Heartbeat != nil && write.ObservedDwellMS == write.Input.Heartbeat.AgeMS
	}
	if decision.Immediate {
		return write.ObservedDwellMS == 0
	}
	expected := previous.DwellMS
	if !write.HubRestarted {
		if write.ElapsedMS > math.MaxInt64-expected {
			expected = math.MaxInt64
		} else {
			expected += write.ElapsedMS
		}
	}
	return write.ObservedDwellMS == expected && expected >= spec.TriggerDwellMS
}

func resolveAlertIncidentTx(ctx context.Context, tx *sql.Tx, record RuleRecord, write AlertEvaluationWrite, instanceID string, reduced alerts.Result) (string, int, error) {
	if reduced.Transition == nil || reduced.Transition.NewState != alerts.StateResolved {
		return "", 0, ErrAlertInvalid
	}
	incidentID, err := requireOpenAlertIncidentTx(ctx, tx, write.DeploymentID, instanceID)
	if err != nil {
		return "", 0, err
	}
	var startMS int64
	if err := tx.QueryRowContext(ctx, `SELECT start_ms FROM incidents WHERE deployment_id=? AND id=? AND workflow_state='open'`, write.DeploymentID, incidentID).Scan(&startMS); err != nil {
		return "", 0, err
	}
	endMS, err := alertIncidentEndMS(startMS, write.EventMS)
	if err != nil {
		return "", 0, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE incidents SET workflow_state='closed',end_ms=?,version=version+1,updated_ms=? WHERE deployment_id=? AND id=? AND workflow_state='open'`, endMS, endMS, write.DeploymentID, incidentID)
	if err != nil {
		return "", 0, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return "", 0, ErrAlertCursorConflict
	}
	if endMS > math.MaxInt64-incidentResolvedRetention.Milliseconds() {
		return "", 0, ErrAlertInvalid
	}
	if _, err := tx.ExecContext(ctx, `UPDATE incident_capsules SET resolved_ms=?,expires_ms=? WHERE deployment_id=? AND incident_id=? AND resolved_ms IS NULL`, endMS, endMS+incidentResolvedRetention.Milliseconds(), write.DeploymentID, incidentID); err != nil {
		return "", 0, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE outbox SET state='superseded_before_delivery',lease_until_ms=NULL,next_attempt_ms=NULL,last_error_code='newer_alert_state' WHERE deployment_id=? AND instance_id=? AND state IN ('pending','failed','muted')`, write.DeploymentID, instanceID); err != nil {
		return "", 0, err
	}
	intents, err := createAlertOutboxTx(ctx, tx, write.DeploymentID, record, instanceID, incidentID, reduced.Transition.Sequence, reduced.Snapshot.ActiveGeneration, reduced.Snapshot.State, reduced.Snapshot.DataState, write.EventMS, write.Cursor.InputSHA256, reduced.Snapshot.MutedUntilMS)
	if err != nil {
		return "", 0, err
	}
	return incidentID, intents, nil
}

func alertIncidentEndMS(startMS, eventMS int64) (int64, error) {
	if startMS < 0 || eventMS < 0 || startMS == math.MaxInt64 {
		return 0, ErrAlertInvalid
	}
	minimum := startMS + 1
	if eventMS < minimum {
		return minimum, nil
	}
	return eventMS, nil
}

type alertDestination struct {
	ID        string
	Revision  int64
	SecretRef string
}

func createAlertOutboxTx(ctx context.Context, tx *sql.Tx, deploymentID string, record RuleRecord, instanceID, incidentID string, sequence, generation int64, state alerts.State, dataState alerts.DataState, eventMS int64, evidenceHash string, mutedUntil *int64) (int, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id,version,COALESCE(secret_ref,'') FROM destinations WHERE deployment_id=? AND disabled_ms IS NULL ORDER BY id LIMIT ?`, deploymentID, alertDestinationLimit+1)
	if err != nil {
		return 0, err
	}
	destinations := []alertDestination{}
	for rows.Next() {
		var destination alertDestination
		if err := rows.Scan(&destination.ID, &destination.Revision, &destination.SecretRef); err != nil {
			rows.Close()
			return 0, err
		}
		destinations = append(destinations, destination)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	if len(destinations) > alertDestinationLimit {
		return 0, ErrAlertDestinationLimit
	}
	for _, destination := range destinations {
		idempotencyKey := "alert:" + sha256Hex([]byte(fmt.Sprintf("%s/%d/%s/%d", instanceID, sequence, destination.ID, destination.Revision)))
		outboxState := "pending"
		if mutedUntil != nil && *mutedUntil > eventMS {
			outboxState = "muted"
		}
		if err := insertAlertOutboxIntentTx(ctx, tx, deploymentID, record.ID, record.Revision, instanceID, incidentID, destination, sequence, generation, state, dataState, eventMS, eventMS, evidenceHash, idempotencyKey, outboxState); err != nil {
			return 0, err
		}
	}
	return len(destinations), nil
}

func insertAlertOutboxIntentTx(ctx context.Context, tx *sql.Tx, deploymentID, ruleID string, ruleRevision int64, instanceID, incidentID string, destination alertDestination, sequence, generation int64, state alerts.State, dataState alerts.DataState, observedMS, createdMS int64, evidenceHash, idempotencyKey, outboxState string) error {
	outboxID, err := domain.NewUUID()
	if err != nil {
		return err
	}
	payload := struct {
		SchemaVersion      string           `json:"schema_version"`
		EventID            string           `json:"event_id"`
		IdempotencyKey     string           `json:"idempotency_key"`
		IncidentID         string           `json:"incident_id"`
		InstanceID         string           `json:"instance_id"`
		RuleID             string           `json:"rule_id"`
		RuleRevision       int64            `json:"rule_revision"`
		IncidentGeneration int64            `json:"incident_generation"`
		TransitionSequence int64            `json:"transition_sequence"`
		State              alerts.State     `json:"state"`
		DataState          alerts.DataState `json:"data_state"`
		ObservedMS         int64            `json:"observed_ms"`
		EvidenceSHA256     string           `json:"evidence_sha256"`
	}{"alert-notification-1", outboxID, idempotencyKey, incidentID, instanceID, ruleID, ruleRevision, generation, sequence, state, dataState, observedMS, evidenceHash}
	encoded, err := json.Marshal(payload)
	if err != nil || len(encoded) > alertNotificationPayloadMax {
		return ErrAlertInvalid
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO outbox(id,deployment_id,instance_id,transition_seq,destination_id,destination_revision,destination_secret_ref,rule_revision,incident_generation,idempotency_key,payload_json,state,attempts,lease_until_ms,next_attempt_ms,last_error_code,expires_ms,created_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,0,NULL,?,NULL,?,?)`, outboxID, deploymentID, instanceID, sequence, destination.ID, destination.Revision, nullableSecretRefValue(destination.SecretRef), ruleRevision, generation, idempotencyKey, string(encoded), outboxState, createdMS, createdMS+86400000, createdMS); err != nil {
		return err
	}
	return nil
}

func requireOpenAlertIncidentTx(ctx context.Context, tx *sql.Tx, deploymentID, instanceID string) (string, error) {
	var incidentID string
	err := tx.QueryRowContext(ctx, `SELECT id FROM incidents WHERE deployment_id=? AND alert_instance_id=? AND origin='alert' AND workflow_state='open' ORDER BY created_ms,id LIMIT 1`, deploymentID, instanceID).Scan(&incidentID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrAlertCursorConflict
	}
	return incidentID, err
}

func readAlertIncidentIDTx(ctx context.Context, tx *sql.Tx, deploymentID, instanceID string) (*string, error) {
	var incidentID string
	err := tx.QueryRowContext(ctx, `SELECT id FROM incidents WHERE deployment_id=? AND alert_instance_id=? AND origin='alert' ORDER BY created_ms,id LIMIT 1`, deploymentID, instanceID).Scan(&incidentID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &incidentID, nil
}

func readAlertCursorsTx(ctx context.Context, tx *sql.Tx, deploymentID string) (map[string]persistedAlertCursor, error) {
	var encoded string
	if err := tx.QueryRowContext(ctx, `SELECT evaluator_cursor_json FROM maintenance WHERE deployment_id=?`, deploymentID).Scan(&encoded); err != nil {
		return nil, err
	}
	var root map[string]json.RawMessage
	if json.Unmarshal([]byte(encoded), &root) != nil || root == nil {
		return nil, ErrAlertCursorConflict
	}
	cursors := map[string]persistedAlertCursor{}
	if raw, ok := root[alertCursorKey]; ok {
		if json.Unmarshal(raw, &cursors) != nil || len(cursors) > ruleLimit {
			return nil, ErrAlertCursorConflict
		}
	}
	for ruleID, cursor := range cursors {
		if !validUUIDText(ruleID) || cursor.RuleVersion < 1 || !sha256HexPattern.MatchString(cursor.ScopeFingerprint) || cursor.InputOrdinal < 1 || cursor.ObservedThroughMS < 0 || !sha256HexPattern.MatchString(cursor.InputSHA256) || !validUUIDText(cursor.InstanceID) || cursor.TransitionSeq < 0 {
			return nil, ErrAlertCursorConflict
		}
	}
	return cursors, nil
}

func writeAlertCursorsTx(ctx context.Context, tx *sql.Tx, deploymentID string, cursors map[string]persistedAlertCursor, now int64) error {
	if len(cursors) > ruleLimit {
		return ErrAlertCursorConflict
	}
	var encoded string
	if err := tx.QueryRowContext(ctx, `SELECT evaluator_cursor_json FROM maintenance WHERE deployment_id=?`, deploymentID).Scan(&encoded); err != nil {
		return err
	}
	var root map[string]json.RawMessage
	if json.Unmarshal([]byte(encoded), &root) != nil || root == nil {
		return ErrAlertCursorConflict
	}
	raw, err := json.Marshal(cursors)
	if err != nil {
		return err
	}
	root[alertCursorKey] = raw
	updated, err := json.Marshal(root)
	if err != nil || len(updated) > 65536 {
		return ErrAlertCursorConflict
	}
	result, err := tx.ExecContext(ctx, `UPDATE maintenance SET evaluator_cursor_json=?,updated_ms=? WHERE deployment_id=?`, string(updated), now, deploymentID)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrAlertCursorConflict
	}
	return nil
}

const (
	alertPendingIncidentKey = "capacity_pending_alert_incident_bytes"
	alertPendingMetadataKey = "capacity_pending_alert_metadata_bytes"
	alertPendingLiveKey     = "capacity_pending_alert_live_bytes"
)

func readPendingAlertCapacity(encoded string) (incident, metadata, live int64, err error) {
	var root map[string]json.RawMessage
	if json.Unmarshal([]byte(encoded), &root) != nil {
		return 0, 0, 0, ErrAlertCapacity
	}
	for key, target := range map[string]*int64{alertPendingIncidentKey: &incident, alertPendingMetadataKey: &metadata, alertPendingLiveKey: &live} {
		raw, ok := root[key]
		if !ok {
			continue
		}
		if json.Unmarshal(raw, target) != nil || *target < 0 {
			return 0, 0, 0, ErrAlertCapacity
		}
	}
	return incident, metadata, live, nil
}

func writePendingAlertCapacity(ctx context.Context, tx *sql.Tx, deploymentID string, incident, metadata, live int64) error {
	if incident < 0 || metadata < 0 || live < 0 {
		return ErrAlertCapacity
	}
	var encoded string
	if err := tx.QueryRowContext(ctx, `SELECT evaluator_cursor_json FROM maintenance WHERE deployment_id=?`, deploymentID).Scan(&encoded); err != nil {
		return err
	}
	var root map[string]json.RawMessage
	if json.Unmarshal([]byte(encoded), &root) != nil || root == nil {
		return ErrAlertCapacity
	}
	root[alertPendingIncidentKey], _ = json.Marshal(incident)
	root[alertPendingMetadataKey], _ = json.Marshal(metadata)
	root[alertPendingLiveKey], _ = json.Marshal(live)
	updated, err := json.Marshal(root)
	if err != nil || len(updated) > 65536 {
		return ErrAlertCapacity
	}
	_, err = tx.ExecContext(ctx, `UPDATE maintenance SET evaluator_cursor_json=? WHERE deployment_id=?`, string(updated), deploymentID)
	return err
}

func clearPendingAlertCapacityTx(ctx context.Context, tx *sql.Tx, deploymentID string) error {
	return writePendingAlertCapacity(ctx, tx, deploymentID, 0, 0, 0)
}

func readAlertEvaluationResultTx(ctx context.Context, tx *sql.Tx, deploymentID, instanceID string, sequence int64, transitionWritten bool) (AlertEvaluationResult, error) {
	var result AlertEvaluationResult
	result.InstanceID = instanceID
	var value alerts.Snapshot
	var lastValid, opened, resolved, acknowledgedMS, muted sql.NullInt64
	var acknowledgedBy sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT rule_id,rule_version,scope_fingerprint,active_generation,state,data_state,dwell_ms,last_eval_ms,last_valid_ms,opened_ms,resolved_ms,acknowledged_by,acknowledged_ms,muted_until_ms,transition_seq FROM alert_instances WHERE deployment_id=? AND id=?`, deploymentID, instanceID).Scan(&value.RuleID, &value.RuleVersion, &value.ScopeFingerprint, &value.ActiveGeneration, &value.State, &value.DataState, &value.DwellMS, &value.LastEvalMS, &lastValid, &opened, &resolved, &acknowledgedBy, &acknowledgedMS, &muted, &value.TransitionSeq); err != nil {
		return result, err
	}
	var scopeJSON string
	if err := tx.QueryRowContext(ctx, `SELECT scope_json FROM rule_revisions WHERE deployment_id=? AND rule_id=? AND version=?`, deploymentID, value.RuleID, value.RuleVersion).Scan(&scopeJSON); err != nil {
		return result, err
	}
	var scope ruleScope
	if json.Unmarshal([]byte(scopeJSON), &scope) != nil {
		return result, ErrAlertInvalid
	}
	value.IncarnationPolicy = scope.IncarnationPolicy
	value.LastValidMS, value.OpenedMS, value.ResolvedMS = nullableInt64Pointer(lastValid), nullableInt64Pointer(opened), nullableInt64Pointer(resolved)
	value.AcknowledgedBy, value.AcknowledgedMS, value.MutedUntilMS = nullableStringPointer(acknowledgedBy), nullableInt64Pointer(acknowledgedMS), nullableInt64Pointer(muted)
	result.Snapshot = value
	if transitionWritten {
		var transition alerts.Transition
		if err := tx.QueryRowContext(ctx, `SELECT transition_seq,previous_state,new_state,event_ms,evidence_hash FROM alert_transitions WHERE deployment_id=? AND instance_id=? AND transition_seq=?`, deploymentID, instanceID, sequence).Scan(&transition.Sequence, &transition.PreviousState, &transition.NewState, &transition.EventMS, &transition.EvidenceHash); err != nil {
			return result, err
		}
		result.Transition = &transition
	}
	incidentID, err := readAlertIncidentIDTx(ctx, tx, deploymentID, instanceID)
	if err != nil {
		return result, err
	}
	result.IncidentID = incidentID
	if transitionWritten {
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM outbox WHERE deployment_id=? AND instance_id=? AND transition_seq=?`, deploymentID, instanceID, sequence).Scan(&result.OutboxIntents); err != nil {
			return result, err
		}
	}
	return result, nil
}

func validateAlertCapsuleEvidence(definition RuleDefinition, input alerts.Input, evidence AlertCapsuleEvidence) error {
	ruleType := definition.EvaluatorType
	if len(evidence.MetricID) < 1 || len(evidence.MetricID) > 128 || !safeRuleString(evidence.Unit, 32) || evidence.WindowStartMS < 0 || evidence.WindowEndMS <= evidence.WindowStartMS || evidence.ObservedMS < evidence.WindowStartMS || evidence.ObservedMS >= evidence.WindowEndMS || !validCapsuleQuality(evidence.Quality) || !safeRuleString(evidence.DefinitionRevision, 128) || !safeRuleString(evidence.MethodRevision, 128) || len(evidence.SourceSamples) > alertCapsuleSourceLimit || evidence.SourceSampleCount < len(evidence.SourceSamples) || evidence.SourceSampleCount < 0 || evidence.SourceSamplesTruncated != (evidence.SourceSampleCount > len(evidence.SourceSamples)) || len(evidence.RequestSampleIDs) > alertCapsuleSourceLimit || evidence.RequestSampleCount < len(evidence.RequestSampleIDs) || evidence.RequestSampleCount < 0 || evidence.RequestSamplesTruncated != (evidence.RequestSampleCount > len(evidence.RequestSampleIDs)) || len(evidence.Gaps) > alertCapsuleGapLimit || len(evidence.UnavailableReasons) > alertCapsuleReasonLimit {
		return ErrAlertInvalid
	}
	statusEvidenceCount := 0
	if evidence.StatusSample != nil {
		statusEvidenceCount++
		value := evidence.StatusSample
		if !validUUIDText(value.HostID) || !validUUIDText(value.CollectorBootID) || value.SessionGeneration < 1 || value.SessionGeneration > protocol.MaxUint53 || value.Sequence < 0 || value.Sequence > protocol.MaxUint53 || !sha256HexPattern.MatchString(value.PayloadSHA256) || value.ObservedMS < 0 || value.AdmittedMS < 0 {
			return ErrAlertInvalid
		}
	}
	if evidence.StatusAbsence != nil {
		statusEvidenceCount++
		value := evidence.StatusAbsence
		if !validUUIDText(value.HostID) || value.SessionGeneration < 0 || value.SessionGeneration > protocol.MaxUint53 || value.CheckedMS != evidence.ObservedMS || (value.CollectorBootID == nil) != (value.SessionGeneration == 0) || value.CollectorBootID != nil && !validUUIDText(*value.CollectorBootID) {
			return ErrAlertInvalid
		}
	}
	if ruleType == alerts.RuleHostNotReporting || ruleType == alerts.RuleSourceMissing {
		if statusEvidenceCount != 1 {
			return ErrAlertInvalid
		}
	} else if statusEvidenceCount != 0 {
		return ErrAlertInvalid
	}
	if ruleType != alerts.RuleDiskMonitorHealth && ruleType != alerts.RuleObservedRequestDuration && ruleType != alerts.RuleHostNotReporting && ruleType != alerts.RuleSourceMissing && evidence.SourceSampleCount < 1 {
		return ErrAlertInvalid
	}
	if ruleType == alerts.RuleObservedRequestDuration {
		if evidence.RequestSampleCount < 1 || evidence.SourceSampleCount != 0 {
			return ErrAlertInvalid
		}
	} else if evidence.RequestSampleCount != 0 {
		return ErrAlertInvalid
	}
	seen := map[string]bool{}
	for _, sample := range evidence.SourceSamples {
		if !validUUIDText(sample.CollectorBootID) || !validUUIDText(sample.SourceID) || sample.Sequence < 0 || len(sample.ConfigIDs) > alertCapsuleConfigIDLimit {
			return ErrAlertInvalid
		}
		key := fmt.Sprintf("%s/%s/%d", sample.CollectorBootID, sample.SourceID, sample.Sequence)
		if seen[key] {
			return ErrAlertInvalid
		}
		seen[key] = true
		for _, configID := range sample.ConfigIDs {
			if !validUUIDText(configID) && !sha256HexPattern.MatchString(configID) {
				return ErrAlertInvalid
			}
		}
	}
	for _, gap := range evidence.Gaps {
		if gap.StartMS < evidence.WindowStartMS || gap.EndMS <= gap.StartMS || gap.EndMS > evidence.WindowEndMS || !safeRuleCode(gap.Reason) {
			return ErrAlertInvalid
		}
	}
	seenRequest := map[string]bool{}
	for _, sampleID := range evidence.RequestSampleIDs {
		if !validUUIDText(sampleID) || seenRequest[sampleID] {
			return ErrAlertInvalid
		}
		seenRequest[sampleID] = true
	}
	for _, reason := range evidence.UnavailableReasons {
		if !safeRuleCode(reason) {
			return ErrAlertInvalid
		}
	}
	values := 0
	if evidence.NumberValue != nil {
		values++
		if math.IsNaN(*evidence.NumberValue) || math.IsInf(*evidence.NumberValue, 0) {
			return ErrAlertInvalid
		}
	}
	if evidence.StateValue != nil {
		values++
		if !safeRuleCode(*evidence.StateValue) {
			return ErrAlertInvalid
		}
	}
	if evidence.BooleanValue != nil {
		values++
	}
	if values != 1 {
		return ErrAlertInvalid
	}
	switch ruleType {
	case alerts.RuleHeavyCPU:
		if evidence.MetricID != "host.cpu.busy_ratio" || evidence.Unit != "ratio" || evidence.NumberValue == nil || input.CPU == nil || input.CPU.BusyRatio == nil || *evidence.NumberValue != *input.CPU.BusyRatio {
			return ErrAlertInvalid
		}
	case alerts.RuleMemoryPressure:
		if evidence.MetricID != "host.memory.pressure_level" || evidence.Unit != "state" || evidence.StateValue == nil || input.MemoryPressure == nil || *evidence.StateValue != input.MemoryPressure.Level {
			return ErrAlertInvalid
		}
	case alerts.RuleHostNotReporting:
		if evidence.MetricID != "collector.heartbeat_age_ms" || evidence.Unit != "milliseconds" || evidence.NumberValue == nil || input.Heartbeat == nil || *evidence.NumberValue != float64(input.Heartbeat.AgeMS) {
			return ErrAlertInvalid
		}
	case alerts.RuleOllamaUnreachable:
		if evidence.MetricID != "runtime.reachable" || evidence.Unit != "boolean" || evidence.BooleanValue == nil || input.Reachability == nil || input.Reachability.Reachable == nil || *evidence.BooleanValue != *input.Reachability.Reachable {
			return ErrAlertInvalid
		}
	case alerts.RuleSourceMissing:
		if evidence.MetricID != "runtime.source.available" || evidence.Unit != "boolean" || evidence.BooleanValue == nil || input.Source == nil || input.Source.Available == nil || *evidence.BooleanValue != *input.Source.Available {
			return ErrAlertInvalid
		}
	case alerts.RuleObservedRequestDuration:
		if input.Request == nil || evidence.MetricID != input.Request.MetricID || evidence.Unit != "milliseconds" || evidence.NumberValue == nil || evidence.ValidN == nil || evidence.CompletedN == nil || *evidence.ValidN != input.Request.ValidN || *evidence.CompletedN != input.Request.CompletedN {
			return ErrAlertInvalid
		}
		value := input.Request.MedianMS
		if definition.Aggregation != nil && *definition.Aggregation == "p95" {
			value = input.Request.P95MS
		}
		if value == nil || *evidence.NumberValue != *value {
			return ErrAlertInvalid
		}
	case alerts.RuleDiskMonitorHealth:
		if input.MonitorHealth == nil || !validMonitorHealthEvidence(input.MonitorHealth, evidence) {
			return ErrAlertInvalid
		}
	default:
		return ErrAlertInvalid
	}
	return nil
}

func normalizeAlertCapsuleEvidence(evidence AlertCapsuleEvidence) AlertCapsuleEvidence {
	if evidence.SourceSamples == nil {
		evidence.SourceSamples = []AlertSourceSample{}
	}
	for index := range evidence.SourceSamples {
		if evidence.SourceSamples[index].ConfigIDs == nil {
			evidence.SourceSamples[index].ConfigIDs = []string{}
		}
	}
	if evidence.RequestSampleIDs == nil {
		evidence.RequestSampleIDs = []string{}
	}
	if evidence.Gaps == nil {
		evidence.Gaps = []AlertEvidenceGap{}
	}
	if evidence.UnavailableReasons == nil {
		evidence.UnavailableReasons = []string{}
	}
	return evidence
}

func validateAlertEvidenceReferencesTx(ctx context.Context, tx *sql.Tx, deploymentID string, definition RuleDefinition, evidence AlertCapsuleEvidence) error {
	for _, sample := range evidence.SourceSamples {
		var count int
		err := tx.QueryRowContext(ctx, `SELECT count(*) FROM source_frames f JOIN hosts h ON h.deployment_id=f.deployment_id AND h.id=f.host_id WHERE f.deployment_id=? AND f.original_collector_boot_id=? AND f.original_source_id=? AND f.original_sequence=? AND f.delivery_mode='current' AND f.session_generation=h.current_session_generation AND f.collector_boot_id=h.last_boot_id`, deploymentID, sample.CollectorBootID, sample.SourceID, sample.Sequence).Scan(&count)
		if err != nil || count != 1 {
			return ErrAlertInvalid
		}
	}
	if evidence.StatusSample != nil {
		value := evidence.StatusSample
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM source_status s JOIN hosts h ON h.deployment_id=s.deployment_id AND h.id=s.host_id WHERE s.deployment_id=? AND s.host_id=? AND s.collector_boot_id=? AND s.session_generation=? AND s.sequence=? AND s.payload_sha256=? AND s.observed_ms=? AND s.admitted_ms=? AND h.current_session_generation=s.session_generation AND h.last_boot_id=s.collector_boot_id`, deploymentID, value.HostID, value.CollectorBootID, value.SessionGeneration, value.Sequence, value.PayloadSHA256, value.ObservedMS, value.AdmittedMS).Scan(&count); err != nil || count != 1 {
			return ErrAlertInvalid
		}
	}
	if evidence.StatusAbsence != nil {
		value := evidence.StatusAbsence
		var createdMS int64
		if err := tx.QueryRowContext(ctx, `SELECT h.created_ms FROM hosts h WHERE h.deployment_id=? AND h.id=? AND h.retired_ms IS NULL AND h.current_session_generation=? AND h.last_boot_id IS ? AND NOT EXISTS (SELECT 1 FROM source_status s WHERE s.deployment_id=h.deployment_id AND s.host_id=h.id AND s.session_generation=h.current_session_generation AND s.collector_boot_id=h.last_boot_id)`, deploymentID, value.HostID, value.SessionGeneration, value.CollectorBootID).Scan(&createdMS); err != nil {
			return ErrAlertInvalid
		}
		if definition.EvaluatorType == alerts.RuleHostNotReporting && (createdMS > math.MaxInt64-60_000 || value.CheckedMS < createdMS+60_000) {
			return ErrAlertInvalid
		}
	}
	if definition.EvaluatorType != alerts.RuleObservedRequestDuration {
		return nil
	}
	column := map[string]string{
		"request.client.first_byte_ms":            "client_first_byte_ms",
		"request.client.first_content_ms":         "client_first_content_ms",
		"request.client.total_ms":                 "client_total_ms",
		"request.runtime.total_duration_ms":       "runtime_total_duration_ms",
		"request.runtime.load_duration_ms":        "runtime_load_duration_ms",
		"request.runtime.prompt_eval_duration_ms": "runtime_prompt_eval_duration_ms",
		"request.runtime.eval_duration_ms":        "runtime_eval_duration_ms",
	}[*definition.MetricID]
	if column == "" {
		return ErrAlertInvalid
	}
	query := `SELECT count(*) FROM request_samples WHERE deployment_id=? AND target_id=? AND sample_id=? AND terminal_status='completed' AND ` + column + ` IS NOT NULL`
	for _, sampleID := range evidence.RequestSampleIDs {
		var count int
		if err := tx.QueryRowContext(ctx, query, deploymentID, definition.ScopeID, sampleID).Scan(&count); err != nil || count != 1 {
			return ErrAlertInvalid
		}
	}
	return nil
}

func validateAlertStatusEvidenceFence(fence AlertEvaluationFence, evidence AlertCapsuleEvidence) error {
	if evidence.StatusSample == nil && evidence.StatusAbsence == nil {
		return nil
	}
	if fence.Host == nil {
		return ErrAlertInvalid
	}
	if evidence.StatusSample != nil {
		value := evidence.StatusSample
		status := fence.Host.Status
		if status == nil || fence.Host.CollectorBootID == nil || value.HostID != fence.Host.HostID || value.CollectorBootID != *fence.Host.CollectorBootID || value.SessionGeneration != fence.Host.SessionGeneration || value.Sequence != status.Sequence || value.PayloadSHA256 != status.PayloadSHA256 || value.ObservedMS != status.ObservedMS || value.AdmittedMS != status.AdmittedMS {
			return ErrAlertInvalid
		}
		return nil
	}
	value := evidence.StatusAbsence
	if fence.Host.Status != nil || value.HostID != fence.Host.HostID || value.SessionGeneration != fence.Host.SessionGeneration || !equalOptionalString(value.CollectorBootID, fence.Host.CollectorBootID) {
		return ErrAlertInvalid
	}
	return nil
}

func validMonitorHealthEvidence(input *alerts.MonitorHealthInput, evidence AlertCapsuleEvidence) bool {
	switch evidence.MetricID {
	case "monitor.storage_pressure":
		return evidence.Unit == "boolean" && evidence.BooleanValue != nil && input.StoragePressure != nil && *evidence.BooleanValue == *input.StoragePressure
	case "monitor.evaluator_lag_ms":
		return evidence.Unit == "milliseconds" && evidence.NumberValue != nil && input.EvaluatorLagMS != nil && *evidence.NumberValue == float64(*input.EvaluatorLagMS)
	case "monitor.final_delivery_failed":
		return evidence.Unit == "boolean" && evidence.BooleanValue != nil && input.FinalDeliveryFailed != nil && *evidence.BooleanValue == *input.FinalDeliveryFailed
	default:
		return false
	}
}

func validCapsuleQuality(value string) bool {
	switch domain.Quality(value) {
	case domain.QualityMeasured, domain.QualityRuntimeReported, domain.QualityOperatorImportedUnverified, domain.QualityDerived, domain.QualityEstimated, domain.QualityDeclared, domain.QualityInferred, domain.QualityUnavailable:
		return true
	default:
		return false
	}
}
