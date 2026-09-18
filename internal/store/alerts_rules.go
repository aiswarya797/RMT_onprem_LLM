package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"unicode"
	"unicode/utf8"

	"rmt.local/monitor/internal/alerts"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
)

const ruleLimit = 64

var (
	ErrRuleNotFound = errors.New("alert rule not found")
	ErrRuleConflict = errors.New("alert rule request conflict")
	ErrRuleRevision = errors.New("alert rule revision conflict")
	ErrRuleLimit    = errors.New("alert rule limit reached")
	ErrRuleInvalid  = errors.New("invalid alert rule definition")
)

// RuleDefinition is byte-for-byte compatible with action-request.schema.json's
// rule definition. Scope kind and incarnation policy are derived from the
// evaluator type and never accepted as caller-controlled fields.
type RuleDefinition struct {
	ExpectedRevision  *int64                 `json:"expected_revision"`
	EvaluatorType     alerts.RuleType        `json:"evaluator_type"`
	ScopeID           string                 `json:"scope_id"`
	Enabled           bool                   `json:"enabled"`
	MetricID          *string                `json:"metric_id"`
	RequestPopulation *RuleRequestPopulation `json:"request_population"`
	Aggregation       *string                `json:"aggregation"`
	Threshold         json.RawMessage        `json:"threshold"`
	DwellMS           int64                  `json:"dwell_ms"`
	RecoveryMS        int64                  `json:"recovery_ms"`
}

type RuleRequestPopulation struct {
	TargetID          string                `json:"target_id"`
	ModelDigest       string                `json:"model_digest"`
	RuntimeVersion    string                `json:"runtime_version"`
	RuntimeBuild      *string               `json:"runtime_build"`
	ConfigRevision    string                `json:"config_revision"`
	ProfileID         string                `json:"profile_id"`
	ProfileSHA256     string                `json:"profile_sha256"`
	Options           RuleGenerationOptions `json:"options"`
	Concurrency       int                   `json:"concurrency"`
	VantageID         string                `json:"vantage_id"`
	ClockMethod       string                `json:"clock_method"`
	SourceKind        string                `json:"source_kind"`
	VerificationState string                `json:"verification_state"`
}

type RuleGenerationOptions struct {
	NumCtx         int      `json:"num_ctx"`
	NumPredict     int      `json:"num_predict"`
	Temperature    *float64 `json:"temperature"`
	Seed           *int64   `json:"seed"`
	Think          *bool    `json:"think"`
	Stream         bool     `json:"stream"`
	ColdWarmPolicy string   `json:"cold_warm_policy"`
}

type RuleRecord struct {
	ID         string         `json:"id"`
	Revision   int64          `json:"revision"`
	Definition RuleDefinition `json:"definition"`
	CreatedMS  int64          `json:"created_ms"`
	UpdatedMS  int64          `json:"updated_ms"`
}

type ruleScope struct {
	ScopeID           string                   `json:"scope_id"`
	ScopeKind         string                   `json:"scope_kind"`
	IncarnationPolicy alerts.IncarnationPolicy `json:"incarnation_policy"`
}

type ruleThreshold struct {
	MetricID          *string                `json:"metric_id"`
	RequestPopulation *RuleRequestPopulation `json:"request_population"`
	Aggregation       *string                `json:"aggregation"`
	Threshold         json.RawMessage        `json:"threshold"`
	DwellMS           int64                  `json:"dwell_ms"`
	RecoveryMS        int64                  `json:"recovery_ms"`
}

func (s *Store) CreateRule(ctx context.Context, actor SessionRecord, idempotencyKey, requestHash string, definition RuleDefinition) (RuleRecord, error) {
	if definition.ExpectedRevision != nil || !validMutationReceipt(idempotencyKey, requestHash) {
		return RuleRecord{}, ErrRuleInvalid
	}
	return s.mutateRule(ctx, actor, "", idempotencyKey, requestHash, definition, true)
}

func (s *Store) UpdateRule(ctx context.Context, actor SessionRecord, ruleID, idempotencyKey, requestHash string, definition RuleDefinition) (RuleRecord, error) {
	if !validUUIDText(ruleID) || definition.ExpectedRevision == nil || *definition.ExpectedRevision < 1 || !validMutationReceipt(idempotencyKey, requestHash) {
		return RuleRecord{}, ErrRuleInvalid
	}
	return s.mutateRule(ctx, actor, ruleID, idempotencyKey, requestHash, definition, false)
}

func (s *Store) mutateRule(ctx context.Context, actor SessionRecord, ruleID, idempotencyKey, requestHash string, definition RuleDefinition, create bool) (RuleRecord, error) {
	scope, threshold, spec, err := validateRuleDefinition(definition)
	if err != nil {
		return RuleRecord{}, err
	}
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return RuleRecord{}, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RuleRecord{}, err
	}
	defer tx.Rollback()
	role, _, err := validateAPITokenActor(ctx, tx, actor)
	if err != nil {
		return RuleRecord{}, err
	}
	if role != "admin" {
		return RuleRecord{}, ErrOwnershipMismatch
	}
	now := s.clock.Now().UnixMilli()
	if record, found, err := readRuleReceipt(ctx, tx, actor, idempotencyKey, requestHash, now); err != nil {
		return RuleRecord{}, err
	} else if found {
		return record, nil
	}
	if err := validateRuleScopeOwnership(ctx, tx, actor.DeploymentID, scope); err != nil {
		return RuleRecord{}, err
	}
	scopeJSON, _ := json.Marshal(scope)
	thresholdJSON, _ := json.Marshal(threshold)
	version := int64(1)
	createdMS := now
	status := 201
	if create {
		var count int64
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM rules WHERE deployment_id=?`, actor.DeploymentID).Scan(&count); err != nil {
			return RuleRecord{}, err
		}
		if count >= ruleLimit {
			return RuleRecord{}, ErrRuleLimit
		}
		ruleID, err = domain.NewUUID()
		if err != nil {
			return RuleRecord{}, err
		}
	} else {
		status = 200
		var current int64
		if err := tx.QueryRowContext(ctx, `SELECT current_version,created_ms FROM rules WHERE deployment_id=? AND id=?`, actor.DeploymentID, ruleID).Scan(&current, &createdMS); errors.Is(err, sql.ErrNoRows) {
			return RuleRecord{}, ErrRuleNotFound
		} else if err != nil {
			return RuleRecord{}, err
		}
		if current != *definition.ExpectedRevision {
			return RuleRecord{}, ErrRuleRevision
		}
		version = current + 1
		if err := supersedeRuleInstancesTx(ctx, tx, actor.DeploymentID, ruleID, current, requestHash, now); err != nil {
			return RuleRecord{}, err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO rule_revisions(deployment_id,rule_id,version,scope_json,evaluator_type,threshold_json,enabled,updated_by,created_ms) VALUES(?,?,?,?,?,?,?,?,?)`, actor.DeploymentID, ruleID, version, string(scopeJSON), string(spec.Type), string(thresholdJSON), boolInt(definition.Enabled), actor.User.ID, now); err != nil {
		if strings.Contains(err.Error(), "rule_cap_64") {
			return RuleRecord{}, ErrRuleLimit
		}
		return RuleRecord{}, err
	}
	if create {
		if _, err := tx.ExecContext(ctx, `INSERT INTO rules(id,deployment_id,current_version,created_ms,updated_ms) VALUES(?,?,?,?,?)`, ruleID, actor.DeploymentID, version, now, now); err != nil {
			return RuleRecord{}, err
		}
	} else {
		result, err := tx.ExecContext(ctx, `UPDATE rules SET current_version=?,updated_ms=? WHERE deployment_id=? AND id=? AND current_version=?`, version, now, actor.DeploymentID, ruleID, *definition.ExpectedRevision)
		if err != nil {
			return RuleRecord{}, err
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			return RuleRecord{}, ErrRuleRevision
		}
	}
	record, err := readRuleTx(ctx, tx, actor.DeploymentID, ruleID)
	if err != nil {
		return RuleRecord{}, err
	}
	auditID, err := domain.NewUUID()
	if err != nil {
		return RuleRecord{}, err
	}
	action := "alert.rule.create"
	if !create {
		action = "alert.rule.update"
	}
	detail, _ := json.Marshal(map[string]any{"revision": version, "evaluator_type": definition.EvaluatorType, "enabled": definition.Enabled})
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit(id,deployment_id,actor_user_id,action,resource_id,time_ms,allowlisted_detail_json) VALUES(?,?,?,?,?,?,?)`, auditID, actor.DeploymentID, actor.User.ID, action, ruleID, now, string(detail)); err != nil {
		return RuleRecord{}, err
	}
	encoded, _ := json.Marshal(record)
	if _, err := tx.ExecContext(ctx, `INSERT INTO idempotency_receipts(deployment_id,deployment_generation,actor_user_id,idempotency_key,request_body_sha256,result_status,result_json,created_ms,expires_ms) VALUES(?,?,?,?,?,?,?,?,?)`, actor.DeploymentID, actor.Generation, actor.User.ID, idempotencyKey, requestHash, status, string(encoded), now, now+86400000); err != nil {
		return RuleRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return RuleRecord{}, err
	}
	return record, nil
}

func (s *Store) ReadRule(ctx context.Context, actor SessionRecord, ruleID string) (RuleRecord, error) {
	if !validUUIDText(ruleID) {
		return RuleRecord{}, ErrRuleInvalid
	}
	if _, _, err := s.validateAPITokenActorRead(ctx, actor); err != nil {
		return RuleRecord{}, err
	}
	return readRuleDB(ctx, s.db, actor.DeploymentID, ruleID)
}

func (s *Store) ListRules(ctx context.Context, actor SessionRecord) ([]RuleRecord, error) {
	if _, _, err := s.validateAPITokenActorRead(ctx, actor); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT r.id FROM rules r WHERE r.deployment_id=? ORDER BY r.created_ms,r.id LIMIT ?`, actor.DeploymentID, ruleLimit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(ids) > ruleLimit {
		return nil, ErrRuleLimit
	}
	records := make([]RuleRecord, 0, len(ids))
	for _, id := range ids {
		record, err := readRuleDB(ctx, s.db, actor.DeploymentID, id)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func readRuleDB(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, deploymentID, ruleID string) (RuleRecord, error) {
	return readRuleQuery(ctx, query, deploymentID, ruleID)
}

func readRuleTx(ctx context.Context, tx *sql.Tx, deploymentID, ruleID string) (RuleRecord, error) {
	return readRuleQuery(ctx, tx, deploymentID, ruleID)
}

func readRuleQuery(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, deploymentID, ruleID string) (RuleRecord, error) {
	var record RuleRecord
	var scopeJSON, thresholdJSON, evaluator string
	var enabled int
	err := query.QueryRowContext(ctx, `SELECT r.id,r.current_version,rr.scope_json,rr.evaluator_type,rr.threshold_json,rr.enabled,r.created_ms,r.updated_ms FROM rules r JOIN rule_revisions rr ON rr.deployment_id=r.deployment_id AND rr.rule_id=r.id AND rr.version=r.current_version WHERE r.deployment_id=? AND r.id=?`, deploymentID, ruleID).Scan(&record.ID, &record.Revision, &scopeJSON, &evaluator, &thresholdJSON, &enabled, &record.CreatedMS, &record.UpdatedMS)
	if errors.Is(err, sql.ErrNoRows) {
		return RuleRecord{}, ErrRuleNotFound
	}
	if err != nil {
		return RuleRecord{}, err
	}
	var scope ruleScope
	var threshold ruleThreshold
	if err := protocol.DecodeStrictJSON(strings.NewReader(scopeJSON), 64<<10, &scope); err != nil {
		return RuleRecord{}, ErrRuleInvalid
	}
	if err := protocol.DecodeStrictJSON(strings.NewReader(thresholdJSON), 64<<10, &threshold); err != nil {
		return RuleRecord{}, ErrRuleInvalid
	}
	record.Definition = RuleDefinition{ExpectedRevision: int64Pointer(record.Revision), EvaluatorType: alerts.RuleType(evaluator), ScopeID: scope.ScopeID, Enabled: enabled == 1, MetricID: threshold.MetricID, RequestPopulation: threshold.RequestPopulation, Aggregation: threshold.Aggregation, Threshold: threshold.Threshold, DwellMS: threshold.DwellMS, RecoveryMS: threshold.RecoveryMS}
	if _, _, _, err := validateRuleDefinition(record.Definition); err != nil {
		return RuleRecord{}, err
	}
	return record, nil
}

func readRuleReceipt(ctx context.Context, tx *sql.Tx, actor SessionRecord, key, requestHash string, now int64) (RuleRecord, bool, error) {
	var storedHash, encoded string
	var expires int64
	err := tx.QueryRowContext(ctx, `SELECT request_body_sha256,result_json,expires_ms FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=?`, actor.DeploymentID, actor.Generation, actor.User.ID, key).Scan(&storedHash, &encoded, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return RuleRecord{}, false, nil
	}
	if err != nil {
		return RuleRecord{}, false, err
	}
	if expires <= now {
		if _, err := tx.ExecContext(ctx, `DELETE FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=?`, actor.DeploymentID, actor.Generation, actor.User.ID, key); err != nil {
			return RuleRecord{}, false, err
		}
		return RuleRecord{}, false, nil
	}
	if storedHash != requestHash {
		return RuleRecord{}, false, ErrRuleConflict
	}
	var record RuleRecord
	if err := protocol.DecodeStrictJSON(strings.NewReader(encoded), 64<<10, &record); err != nil {
		return RuleRecord{}, false, ErrRuleConflict
	}
	return record, true, nil
}

func validateRuleDefinition(definition RuleDefinition) (ruleScope, ruleThreshold, alerts.Spec, error) {
	if !validUUIDText(definition.ScopeID) || definition.DwellMS < 0 || definition.RecoveryMS < 0 || len(definition.Threshold) == 0 {
		return ruleScope{}, ruleThreshold{}, alerts.Spec{}, ErrRuleInvalid
	}
	spec, err := alerts.DefaultSpec(testRuleIdentity, 1, definition.EvaluatorType, strings.Repeat("a", 64))
	if err != nil || definition.DwellMS != spec.TriggerDwellMS || definition.RecoveryMS != spec.RecoveryDwellMS {
		return ruleScope{}, ruleThreshold{}, alerts.Spec{}, ErrRuleInvalid
	}
	scope := ruleScope{ScopeID: definition.ScopeID, IncarnationPolicy: spec.IncarnationPolicy}
	switch definition.EvaluatorType {
	case alerts.RuleHostNotReporting, alerts.RuleMemoryPressure, alerts.RuleHeavyCPU:
		scope.ScopeKind = "host"
	case alerts.RuleOllamaUnreachable, alerts.RuleSourceMissing, alerts.RuleObservedRequestDuration:
		scope.ScopeKind = "target"
	case alerts.RuleDiskMonitorHealth:
		scope.ScopeKind = "deployment"
	default:
		return ruleScope{}, ruleThreshold{}, alerts.Spec{}, ErrRuleInvalid
	}
	threshold := ruleThreshold{MetricID: definition.MetricID, RequestPopulation: definition.RequestPopulation, Aggregation: definition.Aggregation, Threshold: append(json.RawMessage(nil), definition.Threshold...), DwellMS: definition.DwellMS, RecoveryMS: definition.RecoveryMS}
	if definition.EvaluatorType == alerts.RuleObservedRequestDuration {
		if definition.MetricID == nil || definition.RequestPopulation == nil || definition.Aggregation == nil || (*definition.Aggregation != "median" && *definition.Aggregation != "p95") || !validRulePopulation(*definition.RequestPopulation) {
			return ruleScope{}, ruleThreshold{}, alerts.Spec{}, ErrRuleInvalid
		}
		var value float64
		if err := strictRawJSON(definition.Threshold, &value); err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 120_000 {
			return ruleScope{}, ruleThreshold{}, alerts.Spec{}, ErrRuleInvalid
		}
		spec.RequestDuration = &alerts.RequestDurationSpec{MetricID: *definition.MetricID, Statistic: *definition.Aggregation, ThresholdMS: value}
		if err := spec.Validate(); err != nil || definition.RequestPopulation.TargetID != definition.ScopeID {
			return ruleScope{}, ruleThreshold{}, alerts.Spec{}, ErrRuleInvalid
		}
	} else {
		if definition.MetricID != nil || definition.RequestPopulation != nil || definition.Aggregation != nil || !validFixedThreshold(definition.EvaluatorType, definition.Threshold) {
			return ruleScope{}, ruleThreshold{}, alerts.Spec{}, ErrRuleInvalid
		}
	}
	return scope, threshold, spec, nil
}

const testRuleIdentity = "11111111-1111-4111-8111-111111111111"

func validFixedThreshold(ruleType alerts.RuleType, raw json.RawMessage) bool {
	var value any
	if err := strictRawJSON(raw, &value); err != nil {
		return false
	}
	want := map[alerts.RuleType]string{
		alerts.RuleOllamaUnreachable: "null", alerts.RuleHostNotReporting: "60000", alerts.RuleSourceMissing: "null",
		alerts.RuleMemoryPressure: `"warning"`, alerts.RuleHeavyCPU: "0.9", alerts.RuleDiskMonitorHealth: "15000",
	}[ruleType]
	canonical, err := json.Marshal(value)
	return err == nil && string(canonical) == want
}

func strictRawJSON(raw json.RawMessage, target any) error {
	if len(raw) > 64<<10 {
		return ErrRuleInvalid
	}
	return protocol.DecodeStrictJSON(bytes.NewReader(raw), int64(len(raw)), target)
}

func validRulePopulation(value RuleRequestPopulation) bool {
	if !validUUIDText(value.TargetID) || !sha256HexPattern.MatchString(value.ModelDigest) || !sha256HexPattern.MatchString(value.ConfigRevision) || !sha256HexPattern.MatchString(value.ProfileSHA256) || !safeRuleString(value.RuntimeVersion, 256) || value.RuntimeBuild != nil && !safeRuleString(*value.RuntimeBuild, 256) || !safeRuleCode(value.ProfileID) || !safeRuleString(value.VantageID, 256) || value.Concurrency < 1 || value.Concurrency > 4 || value.ClockMethod != "monotonic" {
		return false
	}
	if value.SourceKind == "deliberate_probe" && value.VerificationState != "direct_capture" || value.SourceKind == "imported_test" && value.VerificationState != "operator_imported_unverified" || value.SourceKind != "deliberate_probe" && value.SourceKind != "imported_test" {
		return false
	}
	o := value.Options
	if o.NumCtx < 1 || o.NumCtx > 131072 || o.NumPredict < 1 || o.NumPredict > 4096 || o.Temperature != nil && (math.IsNaN(*o.Temperature) || math.IsInf(*o.Temperature, 0) || *o.Temperature < 0 || *o.Temperature > 2) || o.Seed != nil && (*o.Seed < 0 || *o.Seed > 2147483647) || !o.Stream {
		return false
	}
	return o.ColdWarmPolicy == "cold_model_unloaded" || o.ColdWarmPolicy == "warm_model_reported_loaded" || o.ColdWarmPolicy == "not_controlled"
}

func safeRuleString(value string, maximum int) bool {
	return len(value) >= 1 && len(value) <= maximum && utf8.ValidString(value) && strings.IndexFunc(value, unicode.IsControl) < 0
}

func safeRuleCode(value string) bool {
	if len(value) < 1 || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_') {
			return false
		}
	}
	return true
}

func validateRuleScopeOwnership(ctx context.Context, tx *sql.Tx, deploymentID string, scope ruleScope) error {
	var count int
	switch scope.ScopeKind {
	case "deployment":
		if scope.ScopeID != deploymentID {
			return ErrOwnershipMismatch
		}
		count = 1
	case "host":
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM hosts WHERE deployment_id=? AND id=? AND retired_ms IS NULL`, deploymentID, scope.ScopeID).Scan(&count); err != nil {
			return err
		}
	case "target":
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM targets WHERE deployment_id=? AND id=? AND retired_ms IS NULL`, deploymentID, scope.ScopeID).Scan(&count); err != nil {
			return err
		}
	}
	if count != 1 {
		return ErrOwnershipMismatch
	}
	return nil
}

func supersedeRuleInstancesTx(ctx context.Context, tx *sql.Tx, deploymentID, ruleID string, version int64, evidenceHash string, now int64) error {
	rows, err := tx.QueryContext(ctx, `SELECT id,state,transition_seq FROM alert_instances WHERE deployment_id=? AND rule_id=? AND rule_version=? AND state NOT IN ('RESOLVED','superseded') ORDER BY id LIMIT 1001`, deploymentID, ruleID, version)
	if err != nil {
		return err
	}
	type active struct {
		id, state string
		sequence  int64
	}
	instances := []active{}
	for rows.Next() {
		var value active
		if err := rows.Scan(&value.id, &value.state, &value.sequence); err != nil {
			rows.Close()
			return err
		}
		instances = append(instances, value)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(instances) > 1000 {
		return ErrRuleConflict
	}
	for _, instance := range instances {
		sequence := instance.sequence + 1
		if _, err := tx.ExecContext(ctx, `UPDATE alert_instances SET state='superseded',dwell_ms=0,last_eval_ms=?,transition_seq=? WHERE deployment_id=? AND id=?`, now, sequence, deploymentID, instance.id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO alert_transitions(deployment_id,instance_id,transition_seq,previous_state,new_state,event_ms,evidence_hash) VALUES(?,?,?,?, 'superseded',?,?)`, deploymentID, instance.id, sequence, instance.state, now, evidenceHash); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE outbox SET state='superseded_before_delivery',lease_until_ms=NULL,next_attempt_ms=NULL,last_error_code='rule_superseded' WHERE deployment_id=? AND instance_id IN (SELECT id FROM alert_instances WHERE deployment_id=? AND rule_id=? AND rule_version=?) AND state IN ('pending','failed','muted')`, deploymentID, deploymentID, ruleID, version); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE incidents SET workflow_state='closed',end_ms=COALESCE(end_ms,CASE WHEN start_ms>=? THEN start_ms+1 ELSE ? END),updated_ms=CASE WHEN updated_ms>? THEN updated_ms ELSE ? END WHERE deployment_id=? AND alert_instance_id IN (SELECT id FROM alert_instances WHERE deployment_id=? AND rule_id=? AND rule_version=?) AND workflow_state='open'`, now, now, now, now, deploymentID, deploymentID, ruleID, version); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE incident_capsules SET resolved_ms=COALESCE(resolved_ms,(SELECT i.end_ms FROM incidents i WHERE i.deployment_id=incident_capsules.deployment_id AND i.id=incident_capsules.incident_id)),expires_ms=COALESCE(expires_ms,(SELECT i.end_ms FROM incidents i WHERE i.deployment_id=incident_capsules.deployment_id AND i.id=incident_capsules.incident_id)+?) WHERE deployment_id=? AND incident_id IN (SELECT id FROM incidents WHERE deployment_id=? AND alert_instance_id IN (SELECT id FROM alert_instances WHERE deployment_id=? AND rule_id=? AND rule_version=?))`, incidentResolvedRetention.Milliseconds(), deploymentID, deploymentID, deploymentID, ruleID, version); err != nil {
		return err
	}
	return nil
}

func int64Pointer(value int64) *int64 { return &value }

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func canonicalRuleScopeFingerprint(scope ruleScope) (string, error) {
	encoded, err := json.Marshal(scope)
	if err != nil {
		return "", err
	}
	return sha256Hex(encoded), nil
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return fmt.Sprintf("%x", sum[:])
}
