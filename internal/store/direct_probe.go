package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"rmt.local/monitor/internal/domain"
)

var (
	ErrProbeRunInvalid        = errors.New("invalid direct probe run")
	ErrProbeRunConflict       = errors.New("direct probe request conflict")
	ErrProbeTargetUnavailable = errors.New("direct probe target unavailable")
)

// DirectProbeModel is the durable model identity selected by a live local
// preflight. Parameter and quantization details stay at the runtime boundary;
// the run itself retains only the immutable digest identity.
type DirectProbeModel struct {
	ID     string
	Alias  string
	Digest *string
}

type DirectProbeContext struct {
	DeploymentID     string
	HostID           string
	SourceID         string
	TargetID         string
	ConfigSnapshotID string
	ConfigHash       string
	Models           []DirectProbeModel
}

// DirectProbeReceipt is the versioned local-action result without any model
// content. A blocked result intentionally has no run ID because no request
// sample was submitted.
type DirectProbeReceipt struct {
	Status         string   `json:"status"`
	RunID          *string  `json:"run_id"`
	RequestedCount int      `json:"requested_count"`
	SubmittedCount int      `json:"submitted_count"`
	SafeCode       string   `json:"safe_code"`
	Reasons        []string `json:"reasons"`
}

func (s *Store) ReadDirectProbeContext(ctx context.Context, targetID string) (DirectProbeContext, error) {
	if !validUUIDText(targetID) {
		return DirectProbeContext{}, ErrProbeRunInvalid
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return DirectProbeContext{}, err
	}
	defer tx.Rollback()
	var result DirectProbeContext
	var local int
	var adapterID string
	var endpointAlias string
	err = tx.QueryRowContext(ctx, `SELECT t.deployment_id,t.host_id,t.adapter_id,t.endpoint_alias,EXISTS(SELECT 1 FROM hosts h JOIN audit a ON a.deployment_id=h.deployment_id AND a.resource_id=h.id AND a.action='collector.local_host.register' WHERE h.deployment_id=t.deployment_id AND h.id=t.host_id) FROM targets t WHERE t.id=? AND t.retired_ms IS NULL`, targetID).Scan(&result.DeploymentID, &result.HostID, &adapterID, &endpointAlias, &local)
	if errors.Is(err, sql.ErrNoRows) {
		return DirectProbeContext{}, ErrProbeTargetUnavailable
	}
	if err != nil {
		return DirectProbeContext{}, err
	}
	if local == 0 || adapterID != "ollama" || endpointAlias != "Configured local endpoint" {
		return DirectProbeContext{}, ErrProbeTargetUnavailable
	}
	result.TargetID = targetID
	if err := tx.QueryRowContext(ctx, `SELECT id FROM sources WHERE deployment_id=? AND host_id=? AND target_id=? AND kind='runtime' AND retired_ms IS NULL ORDER BY created_ms DESC,id DESC LIMIT 1`, result.DeploymentID, result.HostID, targetID).Scan(&result.SourceID); errors.Is(err, sql.ErrNoRows) {
		return DirectProbeContext{}, ErrProbeTargetUnavailable
	} else if err != nil {
		return DirectProbeContext{}, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,served_alias,digest FROM model_revisions WHERE deployment_id=? AND host_id=? AND target_id=? AND digest IS NOT NULL ORDER BY created_ms DESC,id DESC LIMIT 64`, result.DeploymentID, result.HostID, targetID)
	if err != nil {
		return DirectProbeContext{}, err
	}
	for rows.Next() {
		var model DirectProbeModel
		var digest sql.NullString
		if err := rows.Scan(&model.ID, &model.Alias, &digest); err != nil {
			rows.Close()
			return DirectProbeContext{}, err
		}
		if digest.Valid && sha256HexPattern.MatchString(digest.String) {
			model.Digest = &digest.String
			result.Models = append(result.Models, model)
		}
	}
	if err := rows.Close(); err != nil {
		return DirectProbeContext{}, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT id,config_hash FROM config_snapshots WHERE deployment_id=? AND host_id=? AND target_id=? ORDER BY observed_ms DESC,id DESC LIMIT 1`, result.DeploymentID, result.HostID, targetID).Scan(&result.ConfigSnapshotID, &result.ConfigHash); errors.Is(err, sql.ErrNoRows) {
		return DirectProbeContext{}, ErrProbeTargetUnavailable
	} else if err != nil {
		return DirectProbeContext{}, err
	}
	if !sha256HexPattern.MatchString(result.ConfigHash) {
		return DirectProbeContext{}, ErrProbeTargetUnavailable
	}
	if err := tx.Commit(); err != nil {
		return DirectProbeContext{}, err
	}
	if result.Models == nil {
		result.Models = []DirectProbeModel{}
	}
	return result, nil
}

func validateDirectProbe(run RequestRun) error {
	if run.SchemaVersion != domain.SchemaVersion || run.SourceKind != "deliberate_probe" || run.VerificationState != "direct_capture" || run.ContentPersistence != "none" || !validUUIDText(run.RunID) || !validUUIDText(run.DeploymentID) || !validUUIDText(run.HostID) || !validUUIDText(run.SourceID) || !validUUIDText(run.TargetID) || !validUUIDText(run.ModelID) || !validUUIDText(run.ConfigSnapshotID) || run.ExpectedCount != 1 || run.SubmittedCount != 1 || len(run.Samples) != 1 || run.DecodedSizeBytes < 1 || run.DecodedSizeBytes > probeImportMaximumBytes || run.FinalizationState != "finalized" || run.PartialReason != nil {
		return ErrProbeRunInvalid
	}
	if !validRulePopulation(run.PopulationKey) || run.PopulationKey.SourceKind != run.SourceKind || run.PopulationKey.VerificationState != run.VerificationState || run.PopulationKey.TargetID != run.TargetID {
		return ErrProbeRunInvalid
	}
	if run.CompletedCount+run.FailedCount+run.CancelledCount+run.IncompleteCount != 1 {
		return ErrProbeRunInvalid
	}
	if err := validateDirectSample(run, run.Samples[0]); err != nil {
		return err
	}
	return nil
}

func validateDirectSample(run RequestRun, sample RequestSample) error {
	if sample.SchemaVersion != domain.SchemaVersion || !validUUIDText(sample.SampleID) || sample.RunID != run.RunID || sample.SourceKind != "deliberate_probe" || sample.VerificationState != "direct_capture" || sample.ObservationScope != "explicit_observed_request" || sample.DeploymentID != run.DeploymentID || sample.HostID != run.HostID || sample.SourceID != run.SourceID || sample.TargetID != run.TargetID || sample.ModelID != run.ModelID || sample.ConfigSnapshotID != run.ConfigSnapshotID || (sample.RuntimeSourcePinID != "ollama-0.34.0-source" && sample.RuntimeSourcePinID != "ollama-0.12.10-source") || sample.RuntimeOperation != "generate" || sample.ContentPersistence != "none" || !validRulePopulation(sample.PopulationKey) || sample.PopulationKey.SourceKind != "deliberate_probe" || sample.PopulationKey.VerificationState != "direct_capture" || sample.SubmittedAtMS < 0 || sample.OffsetsNS.Submit != "0" || sample.OffsetsNS.End == "" || sample.TerminalStatus == "" {
		return ErrProbeRunInvalid
	}
	sampleHash, err := populationKeyHash(sample.PopulationKey)
	runHash, hashErr := populationKeyHash(run.PopulationKey)
	if err != nil || hashErr != nil || sampleHash != runHash {
		return ErrProbeRunInvalid
	}
	if err := validateOffsets(sample.OffsetsNS, sample.Metrics); err != nil {
		return err
	}
	if err := validateSampleHTTPAndTerminal(sample); err != nil {
		return err
	}
	if len(sample.FieldProvenance) != len(requestMetricIDs) {
		return ErrProbeRunInvalid
	}
	for _, metric := range requestMetricIDs {
		provenance, ok := sample.FieldProvenance[metric]
		if !ok || (strings.HasPrefix(metric, "request.client.") && provenance.Source != "client_monotonic") || (strings.HasPrefix(metric, "request.runtime.") && provenance.Source != "ollama_terminal") || provenance.Verification != "direct_capture" || provenance.MissingReason != nil && !validMissingReason(*provenance.MissingReason) {
			return ErrProbeRunInvalid
		}
	}
	return nil
}

func (s *Store) RecordDirectProbe(ctx context.Context, actor SessionRecord, idempotencyKey, requestHash string, run RequestRun) (DirectProbeReceipt, error) {
	if !validMutationReceipt(idempotencyKey, requestHash) || validateDirectProbe(run) != nil {
		return DirectProbeReceipt{}, ErrProbeRunInvalid
	}
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return DirectProbeReceipt{}, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DirectProbeReceipt{}, err
	}
	defer tx.Rollback()
	role, _, err := validateAPITokenActor(ctx, tx, actor)
	if err != nil {
		return DirectProbeReceipt{}, err
	}
	if role != "admin" {
		return DirectProbeReceipt{}, ErrOwnershipMismatch
	}
	now := s.clock.Now().UnixMilli()
	if receipt, found, err := readDirectProbeReceiptTx(ctx, tx, actor, idempotencyKey, requestHash, now); err != nil {
		return DirectProbeReceipt{}, err
	} else if found {
		return receipt, nil
	}
	if run.DeploymentID != actor.DeploymentID {
		return DirectProbeReceipt{}, ErrOwnershipMismatch
	}
	if err := validateImportReferencesTx(ctx, tx, run); err != nil {
		return DirectProbeReceipt{}, err
	}
	var existing int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM request_runs WHERE deployment_id=? AND id=?`, actor.DeploymentID, run.RunID).Scan(&existing); err != nil {
		return DirectProbeReceipt{}, err
	}
	if existing != 0 {
		return DirectProbeReceipt{}, ErrProbeRunConflict
	}
	encoded, err := canonicalJSON(run)
	if err != nil || int64(len(encoded)) > probeImportMaximumBytes {
		return DirectProbeReceipt{}, ErrProbeRunInvalid
	}
	reserved, err := batchCapacityBytes(len(encoded), len(run.Samples))
	if err != nil {
		return DirectProbeReceipt{}, ErrProbeImportCapacity
	}
	if err := s.capacityAdmissionForImportTx(ctx, tx, actor.DeploymentID, now, reserved); err != nil {
		return DirectProbeReceipt{}, err
	}
	populationHash, err := populationKeyHash(run.PopulationKey)
	if err != nil {
		return DirectProbeReceipt{}, ErrProbeRunInvalid
	}
	finalizedMS := now
	if _, err := tx.ExecContext(ctx, `INSERT INTO request_runs(id,deployment_id,host_id,source_id,target_id,source_kind,verification_state,population_key_sha256,population_key_json,expected_count,submitted_count,completed_count,failed_count,cancelled_count,incomplete_count,finalization_state,reserved_records,reserved_bytes,created_ms,finalized_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, run.RunID, actor.DeploymentID, run.HostID, run.SourceID, run.TargetID, run.SourceKind, run.VerificationState, populationHash, string(mustJSON(run.PopulationKey)), run.ExpectedCount, run.SubmittedCount, run.CompletedCount, run.FailedCount, run.CancelledCount, run.IncompleteCount, run.FinalizationState, 1, reserved, now, finalizedMS); err != nil {
		return DirectProbeReceipt{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO request_run_metadata(deployment_id,host_id,run_id,target_id,model_id,config_id,decoded_size_bytes,original_artifact_sha256,partial_reason,content_persistence) VALUES(?,?,?,?,?,?,?,?,?,?)`, actor.DeploymentID, run.HostID, run.RunID, run.TargetID, run.ModelID, run.ConfigSnapshotID, run.DecodedSizeBytes, nil, run.PartialReason, run.ContentPersistence); err != nil {
		return DirectProbeReceipt{}, err
	}
	for _, sample := range run.Samples {
		if err := insertRequestSampleTx(ctx, tx, run, sample, populationHash); err != nil {
			return DirectProbeReceipt{}, err
		}
	}
	status := directProbeStatus(run)
	runID := run.RunID
	receipt := DirectProbeReceipt{Status: status, RunID: &runID, RequestedCount: 1, SubmittedCount: 1, SafeCode: "ok", Reasons: []string{}}
	if err := persistDirectProbeReceiptTx(ctx, tx, actor, idempotencyKey, requestHash, receipt, now); err != nil {
		return DirectProbeReceipt{}, err
	}
	if err := writeComparisonAuditTx(ctx, tx, actor, "probe.run_local", run.RunID, now, map[string]any{"target_id": run.TargetID, "model_id": run.ModelID, "source_kind": run.SourceKind, "verification_state": run.VerificationState, "submitted_count": 1}); err != nil {
		return DirectProbeReceipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return DirectProbeReceipt{}, err
	}
	return receipt, nil
}

func directProbeStatus(run RequestRun) string {
	switch {
	case run.CompletedCount == 1:
		return "succeeded"
	case run.CancelledCount == 1:
		return "cancelled"
	case run.IncompleteCount == 1:
		return "partial"
	default:
		return "failed"
	}
}

func (s *Store) RecordDirectProbeBlock(ctx context.Context, actor SessionRecord, idempotencyKey, requestHash, targetID, safeCode string, reasons []string) (DirectProbeReceipt, error) {
	if !validMutationReceipt(idempotencyKey, requestHash) || !validUUIDText(targetID) || !safeRuleCode(safeCode) {
		return DirectProbeReceipt{}, ErrProbeRunInvalid
	}
	for _, reason := range reasons {
		if !safeRuleCode(reason) {
			return DirectProbeReceipt{}, ErrProbeRunInvalid
		}
	}
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return DirectProbeReceipt{}, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DirectProbeReceipt{}, err
	}
	defer tx.Rollback()
	role, _, err := validateAPITokenActor(ctx, tx, actor)
	if err != nil {
		return DirectProbeReceipt{}, err
	}
	if role != "admin" {
		return DirectProbeReceipt{}, ErrOwnershipMismatch
	}
	var targetCount int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM targets WHERE deployment_id=? AND id=? AND retired_ms IS NULL`, actor.DeploymentID, targetID).Scan(&targetCount); err != nil {
		return DirectProbeReceipt{}, err
	}
	if targetCount != 1 {
		return DirectProbeReceipt{}, ErrProbeTargetUnavailable
	}
	now := s.clock.Now().UnixMilli()
	if receipt, found, err := readDirectProbeReceiptTx(ctx, tx, actor, idempotencyKey, requestHash, now); err != nil {
		return DirectProbeReceipt{}, err
	} else if found {
		return receipt, nil
	}
	receipt := DirectProbeReceipt{Status: "blocked", RequestedCount: 1, SubmittedCount: 0, SafeCode: safeCode, Reasons: append([]string(nil), reasons...)}
	if err := persistDirectProbeReceiptTx(ctx, tx, actor, idempotencyKey, requestHash, receipt, now); err != nil {
		return DirectProbeReceipt{}, err
	}
	if err := writeComparisonAuditTx(ctx, tx, actor, "probe.run_local.blocked", targetID, now, map[string]any{"target_id": targetID, "safe_code": safeCode, "reasons": reasons, "request_submitted": false}); err != nil {
		return DirectProbeReceipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return DirectProbeReceipt{}, err
	}
	return receipt, nil
}

func readDirectProbeReceiptTx(ctx context.Context, tx *sql.Tx, actor SessionRecord, key, requestHash string, now int64) (DirectProbeReceipt, bool, error) {
	var storedHash, encoded string
	var expires int64
	err := tx.QueryRowContext(ctx, `SELECT request_body_sha256,result_json,expires_ms FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=?`, actor.DeploymentID, actor.Generation, actor.User.ID, key).Scan(&storedHash, &encoded, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return DirectProbeReceipt{}, false, nil
	}
	if err != nil {
		return DirectProbeReceipt{}, false, err
	}
	if expires <= now {
		if _, err := tx.ExecContext(ctx, `DELETE FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=?`, actor.DeploymentID, actor.Generation, actor.User.ID, key); err != nil {
			return DirectProbeReceipt{}, false, err
		}
		return DirectProbeReceipt{}, false, nil
	}
	var receipt DirectProbeReceipt
	if storedHash != requestHash || json.Unmarshal([]byte(encoded), &receipt) != nil || !validDirectProbeReceipt(receipt) {
		return DirectProbeReceipt{}, false, ErrProbeRunConflict
	}
	return receipt, true, nil
}

func persistDirectProbeReceiptTx(ctx context.Context, tx *sql.Tx, actor SessionRecord, key, requestHash string, receipt DirectProbeReceipt, now int64) error {
	if !validDirectProbeReceipt(receipt) {
		return ErrProbeRunInvalid
	}
	encoded, err := json.Marshal(receipt)
	if err != nil || len(encoded) > 65536 {
		return ErrProbeRunInvalid
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO idempotency_receipts(deployment_id,deployment_generation,actor_user_id,idempotency_key,request_body_sha256,result_status,result_json,created_ms,expires_ms) VALUES(?,?,?,?,?,200,?,?,?)`, actor.DeploymentID, actor.Generation, actor.User.ID, key, requestHash, string(encoded), now, now+int64(24*time.Hour/time.Millisecond))
	return err
}

func validDirectProbeReceipt(receipt DirectProbeReceipt) bool {
	if receipt.Status != "succeeded" && receipt.Status != "partial" && receipt.Status != "failed" && receipt.Status != "cancelled" && receipt.Status != "blocked" || receipt.RequestedCount != 1 || receipt.SubmittedCount < 0 || receipt.SubmittedCount > 1 || !safeRuleCode(receipt.SafeCode) {
		return false
	}
	if len(receipt.Reasons) > 8 {
		return false
	}
	for _, reason := range receipt.Reasons {
		if !safeRuleCode(reason) {
			return false
		}
	}
	return receipt.RunID == nil && receipt.SubmittedCount == 0 || receipt.RunID != nil && validUUIDText(*receipt.RunID) && receipt.SubmittedCount == 1
}
