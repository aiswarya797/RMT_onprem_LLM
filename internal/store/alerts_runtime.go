package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"time"

	"rmt.local/monitor/internal/alerts"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
)

// AlertStartupGrace is the fixed target-episode grace used by both the query
// evaluator and the transactional episode validator.
const AlertStartupGrace = 5 * time.Minute

// AlertRuntimePlan is the bounded, actor-free evaluator read model. It is
// available only for the current normal deployment generation and contains
// exact fences that ApplyAlertEvaluation revalidates in its write transaction.
type AlertRuntimePlan struct {
	DeploymentID         string                     `json:"deployment_id"`
	DeploymentGeneration string                     `json:"deployment_generation"`
	Rules                []AlertRuntimeRulePlan     `json:"rules"`
	Hosts                []AlertRuntimeHostFence    `json:"hosts"`
	Targets              []AlertRuntimeTargetFence  `json:"targets"`
	Episodes             []AlertReachabilityEpisode `json:"episodes"`
	Monitor              AlertRuntimeMonitorFacts   `json:"monitor"`
}

type AlertRuntimeRulePlan struct {
	Rule     RuleRecord        `json:"rule"`
	Cursor   *AlertInputCursor `json:"cursor"`
	Snapshot *alerts.Snapshot  `json:"snapshot"`
}

type AlertRuntimeHostFence struct {
	HostID            string                   `json:"host_id"`
	CreatedMS         int64                    `json:"created_ms"`
	SessionGeneration int64                    `json:"session_generation"`
	CollectorBootID   *string                  `json:"collector_boot_id"`
	Status            *AlertRuntimeStatusFence `json:"status"`
}

type AlertRuntimeStatusFence struct {
	Sequence      int64                  `json:"sequence"`
	PayloadSHA256 string                 `json:"payload_sha256"`
	ObservedMS    int64                  `json:"observed_ms"`
	AdmittedMS    int64                  `json:"admitted_ms"`
	Heartbeat     string                 `json:"heartbeat"`
	Sources       []protocol.SourceState `json:"sources"`
}

type AlertRuntimeTargetFence struct {
	HostID            string  `json:"host_id"`
	TargetID          string  `json:"target_id"`
	LocalSelectorHash string  `json:"local_selector_hash"`
	CreatedMS         int64   `json:"created_ms"`
	ConfigID          *string `json:"config_id"`
	ConfigHash        *string `json:"config_hash"`
	ConfigObservedMS  *int64  `json:"config_observed_ms"`
}

type AlertReachabilityEpisode struct {
	HostID            string `json:"host_id"`
	TargetID          string `json:"target_id"`
	EpisodeID         string `json:"episode_id"`
	StartMS           int64  `json:"start_ms"`
	StartupDeadlineMS int64  `json:"startup_deadline_ms"`
	LastReachableMS   *int64 `json:"last_reachable_ms"`
	EverReachable     bool   `json:"ever_reachable"`
	ExitCount         int64  `json:"exit_count"`
}

type AlertRuntimeMonitorFacts struct {
	StorageState        string `json:"storage_state"`
	CapacityObservedMS  *int64 `json:"capacity_observed_ms"`
	FinalDeliveryFailed bool   `json:"final_delivery_failed"`
}

type AlertEvaluationFence struct {
	Host   *AlertRuntimeHostFence   `json:"host"`
	Target *AlertRuntimeTargetFence `json:"target"`
}

// AlertReachabilityEpisodeWrite advances only evidence-derived episode facts.
// A nil Expected value asserts that no active episode existed in the read plan.
type AlertReachabilityEpisodeWrite struct {
	Target     AlertRuntimeTargetFence   `json:"target"`
	Expected   *AlertReachabilityEpisode `json:"expected"`
	ObservedMS int64                     `json:"observed_ms"`
	Reachable  *bool                     `json:"reachable"`
}

func (s *Store) ReadAlertRuntimePlan(ctx context.Context, deploymentID, deploymentGeneration string) (AlertRuntimePlan, error) {
	if !validUUIDText(deploymentID) || !validUUIDText(deploymentGeneration) {
		return AlertRuntimePlan{}, ErrAlertInvalid
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return AlertRuntimePlan{}, err
	}
	defer tx.Rollback()
	result := AlertRuntimePlan{DeploymentID: deploymentID, DeploymentGeneration: deploymentGeneration, Rules: []AlertRuntimeRulePlan{}, Hosts: []AlertRuntimeHostFence{}, Targets: []AlertRuntimeTargetFence{}, Episodes: []AlertReachabilityEpisode{}}
	var currentGeneration, recoveryState, cursorJSON string
	if err := tx.QueryRowContext(ctx, `SELECT d.deployment_generation,d.recovery_state,m.storage_state,m.evaluator_cursor_json FROM deployments d JOIN maintenance m ON m.deployment_id=d.id WHERE d.id=?`, deploymentID).Scan(&currentGeneration, &recoveryState, &result.Monitor.StorageState, &cursorJSON); err != nil {
		return AlertRuntimePlan{}, ErrAdmissionFenced
	}
	if currentGeneration != deploymentGeneration || recoveryState != "normal" {
		return AlertRuntimePlan{}, ErrAdmissionFenced
	}
	result.Monitor.CapacityObservedMS = alertCapacityObservedMS(cursorJSON)
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM outbox WHERE deployment_id=? AND state IN ('failed','expired') AND next_attempt_ms IS NULL)`, deploymentID).Scan(&result.Monitor.FinalDeliveryFailed); err != nil {
		return AlertRuntimePlan{}, err
	}
	if err := readAlertRuntimeRulesTx(ctx, tx, deploymentID, &result); err != nil {
		return AlertRuntimePlan{}, err
	}
	if err := readAlertRuntimeHostsTx(ctx, tx, deploymentID, &result); err != nil {
		return AlertRuntimePlan{}, err
	}
	if err := readAlertRuntimeTargetsTx(ctx, tx, deploymentID, &result); err != nil {
		return AlertRuntimePlan{}, err
	}
	if err := tx.Commit(); err != nil {
		return AlertRuntimePlan{}, err
	}
	return result, nil
}

func readAlertRuntimeRulesTx(ctx context.Context, tx *sql.Tx, deploymentID string, plan *AlertRuntimePlan) error {
	cursors, err := readAlertCursorsTx(ctx, tx, deploymentID)
	if err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT r.id FROM rules r JOIN rule_revisions v ON v.deployment_id=r.deployment_id AND v.rule_id=r.id AND v.version=r.current_version WHERE r.deployment_id=? AND v.enabled=1 ORDER BY r.created_ms,r.id LIMIT ?`, deploymentID, ruleLimit+1)
	if err != nil {
		return err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(ids) > ruleLimit {
		return ErrRuleLimit
	}
	for _, id := range ids {
		record, err := readRuleTx(ctx, tx, deploymentID, id)
		if err != nil {
			return err
		}
		scope, _, spec, err := validateRuleDefinition(record.Definition)
		if err != nil {
			return err
		}
		spec.RuleID, spec.Version = record.ID, record.Revision
		spec.ScopeFingerprint, err = canonicalRuleScopeFingerprint(scope)
		if err != nil {
			return err
		}
		entry := AlertRuntimeRulePlan{Rule: record}
		if cursor, ok := cursors[id]; ok && cursor.RuleVersion == record.Revision && cursor.ScopeFingerprint == spec.ScopeFingerprint {
			value := AlertInputCursor{InputOrdinal: cursor.InputOrdinal, ObservedThroughMS: cursor.ObservedThroughMS, InputSHA256: cursor.InputSHA256}
			entry.Cursor = &value
		}
		entry.Snapshot, err = readAlertRuntimeSnapshotTx(ctx, tx, deploymentID, spec)
		if err != nil {
			return err
		}
		plan.Rules = append(plan.Rules, entry)
	}
	return nil
}

func readAlertRuntimeSnapshotTx(ctx context.Context, tx *sql.Tx, deploymentID string, spec alerts.Spec) (*alerts.Snapshot, error) {
	var value alerts.Snapshot
	var lastValid, opened, resolved, acknowledgedMS, muted sql.NullInt64
	var acknowledgedBy sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT active_generation,state,data_state,dwell_ms,last_eval_ms,last_valid_ms,opened_ms,resolved_ms,acknowledged_by,acknowledged_ms,muted_until_ms,transition_seq FROM alert_instances WHERE deployment_id=? AND rule_id=? AND rule_version=? AND scope_fingerprint=? ORDER BY active_generation DESC LIMIT 1`, deploymentID, spec.RuleID, spec.Version, spec.ScopeFingerprint).Scan(&value.ActiveGeneration, &value.State, &value.DataState, &value.DwellMS, &value.LastEvalMS, &lastValid, &opened, &resolved, &acknowledgedBy, &acknowledgedMS, &muted, &value.TransitionSeq)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	value.RuleID, value.RuleVersion, value.ScopeFingerprint, value.IncarnationPolicy = spec.RuleID, spec.Version, spec.ScopeFingerprint, spec.IncarnationPolicy
	value.LastValidMS, value.OpenedMS, value.ResolvedMS = nullableInt64Pointer(lastValid), nullableInt64Pointer(opened), nullableInt64Pointer(resolved)
	value.AcknowledgedBy, value.AcknowledgedMS, value.MutedUntilMS = nullableStringPointer(acknowledgedBy), nullableInt64Pointer(acknowledgedMS), nullableInt64Pointer(muted)
	return &value, nil
}

func readAlertRuntimeHostsTx(ctx context.Context, tx *sql.Tx, deploymentID string, plan *AlertRuntimePlan) error {
	rows, err := tx.QueryContext(ctx, `SELECT id,created_ms,current_session_generation,last_boot_id FROM hosts WHERE deployment_id=? AND retired_ms IS NULL ORDER BY created_ms,id LIMIT 3`, deploymentID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var host AlertRuntimeHostFence
		var boot sql.NullString
		if err := rows.Scan(&host.HostID, &host.CreatedMS, &host.SessionGeneration, &boot); err != nil {
			return err
		}
		host.CollectorBootID = nullableStringPointer(boot)
		if host.SessionGeneration > 0 && host.CollectorBootID != nil {
			status, err := readAlertRuntimeStatusTx(ctx, tx, deploymentID, host)
			if err != nil {
				return err
			}
			host.Status = status
		}
		plan.Hosts = append(plan.Hosts, host)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(plan.Hosts) > 2 {
		return ErrAlertInvalid
	}
	return nil
}

func readAlertRuntimeStatusTx(ctx context.Context, tx *sql.Tx, deploymentID string, host AlertRuntimeHostFence) (*AlertRuntimeStatusFence, error) {
	var payload string
	var result AlertRuntimeStatusFence
	err := tx.QueryRowContext(ctx, `SELECT sequence,payload_sha256,observed_ms,admitted_ms,payload_json FROM source_status WHERE deployment_id=? AND host_id=? AND session_generation=? AND collector_boot_id=? ORDER BY sequence DESC LIMIT 1`, deploymentID, host.HostID, host.SessionGeneration, *host.CollectorBootID).Scan(&result.Sequence, &result.PayloadSHA256, &result.ObservedMS, &result.AdmittedMS, &payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var status protocol.SourceStatus
	if json.Unmarshal([]byte(payload), &status) != nil || status.Validate() != nil || status.DeploymentID != deploymentID || status.HostID != host.HostID || status.SessionGeneration != host.SessionGeneration || status.CollectorBootID != *host.CollectorBootID || status.Sequence != result.Sequence || status.ObservedWallMS != result.ObservedMS {
		return nil, ErrAlertCursorConflict
	}
	digest := sha256.Sum256([]byte(payload))
	if hex.EncodeToString(digest[:]) != result.PayloadSHA256 {
		return nil, ErrAlertCursorConflict
	}
	result.Heartbeat = status.Heartbeat
	result.Sources = append([]protocol.SourceState{}, status.Sources...)
	return &result, nil
}

func readAlertRuntimeTargetsTx(ctx context.Context, tx *sql.Tx, deploymentID string, plan *AlertRuntimePlan) error {
	rows, err := tx.QueryContext(ctx, `SELECT id,host_id,local_selector_hash,created_ms FROM targets WHERE deployment_id=? AND retired_ms IS NULL ORDER BY created_ms,id LIMIT 3`, deploymentID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var target AlertRuntimeTargetFence
		if err := rows.Scan(&target.TargetID, &target.HostID, &target.LocalSelectorHash, &target.CreatedMS); err != nil {
			return err
		}
		var configID, configHash sql.NullString
		var configObserved sql.NullInt64
		err := tx.QueryRowContext(ctx, `SELECT id,config_hash,observed_ms FROM config_snapshots WHERE deployment_id=? AND host_id=? AND target_id=? ORDER BY observed_ms DESC,id DESC LIMIT 1`, deploymentID, target.HostID, target.TargetID).Scan(&configID, &configHash, &configObserved)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		target.ConfigID, target.ConfigHash, target.ConfigObservedMS = nullableStringPointer(configID), nullableStringPointer(configHash), nullableInt64Pointer(configObserved)
		plan.Targets = append(plan.Targets, target)
		episode, err := readActiveAlertEpisodeTx(ctx, tx, deploymentID, target.HostID, target.TargetID)
		if err != nil {
			return err
		}
		if episode != nil {
			plan.Episodes = append(plan.Episodes, *episode)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(plan.Targets) > 2 {
		return ErrAlertInvalid
	}
	return nil
}

func readActiveAlertEpisodeTx(ctx context.Context, tx *sql.Tx, deploymentID, hostID, targetID string) (*AlertReachabilityEpisode, error) {
	rows, err := tx.QueryContext(ctx, `SELECT episode_id,start_ms,startup_deadline_ms,last_reachable_ms,ever_reachable,exit_count FROM reachability_episodes WHERE deployment_id=? AND host_id=? AND target_id=? AND ended_ms IS NULL ORDER BY start_ms,episode_id LIMIT 2`, deploymentID, hostID, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result *AlertReachabilityEpisode
	for rows.Next() {
		if result != nil {
			return nil, ErrAlertCursorConflict
		}
		var value AlertReachabilityEpisode
		var last sql.NullInt64
		var ever int
		if err := rows.Scan(&value.EpisodeID, &value.StartMS, &value.StartupDeadlineMS, &last, &ever, &value.ExitCount); err != nil {
			return nil, err
		}
		value.HostID, value.TargetID, value.LastReachableMS, value.EverReachable = hostID, targetID, nullableInt64Pointer(last), ever == 1
		result = &value
	}
	return result, rows.Err()
}

func alertCapacityObservedMS(encoded string) *int64 {
	var root map[string]json.RawMessage
	if json.Unmarshal([]byte(encoded), &root) != nil {
		return nil
	}
	var value int64
	if raw, ok := root["capacity_observed_ms"]; !ok || json.Unmarshal(raw, &value) != nil || value < 0 {
		return nil
	}
	return &value
}

func validateAlertEvaluationFenceTx(ctx context.Context, tx *sql.Tx, deploymentID string, scope ruleScope, definition RuleDefinition, fence AlertEvaluationFence) error {
	switch scope.ScopeKind {
	case "deployment":
		if fence.Host != nil || fence.Target != nil {
			return ErrAlertCursorConflict
		}
		return nil
	case "host":
		if fence.Host == nil || fence.Target != nil || fence.Host.HostID != scope.ScopeID {
			return ErrAlertCursorConflict
		}
	case "target":
		if fence.Host == nil || fence.Target == nil || fence.Target.TargetID != scope.ScopeID || fence.Target.HostID != fence.Host.HostID {
			return ErrAlertCursorConflict
		}
	default:
		return ErrAlertCursorConflict
	}
	currentHost, err := readExactAlertHostFenceTx(ctx, tx, deploymentID, fence.Host.HostID)
	if err != nil || !equalAlertHostFence(*fence.Host, currentHost) {
		return ErrAlertCursorConflict
	}
	if fence.Target != nil {
		currentTarget, err := readExactAlertTargetFenceTx(ctx, tx, deploymentID, fence.Target.HostID, fence.Target.TargetID)
		if err != nil || !equalAlertTargetFence(*fence.Target, currentTarget) {
			return ErrAlertCursorConflict
		}
		if definition.EvaluatorType == alerts.RuleObservedRequestDuration && (definition.RequestPopulation == nil || currentTarget.ConfigHash == nil || *currentTarget.ConfigHash != definition.RequestPopulation.ConfigRevision) {
			return ErrAlertCursorConflict
		}
	}
	return nil
}

func readExactAlertHostFenceTx(ctx context.Context, tx *sql.Tx, deploymentID, hostID string) (AlertRuntimeHostFence, error) {
	var result AlertRuntimeHostFence
	var boot sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT id,created_ms,current_session_generation,last_boot_id FROM hosts WHERE deployment_id=? AND id=? AND retired_ms IS NULL`, deploymentID, hostID).Scan(&result.HostID, &result.CreatedMS, &result.SessionGeneration, &boot); err != nil {
		return result, err
	}
	result.CollectorBootID = nullableStringPointer(boot)
	if result.SessionGeneration > 0 && result.CollectorBootID != nil {
		status, err := readAlertRuntimeStatusTx(ctx, tx, deploymentID, result)
		if err != nil {
			return result, err
		}
		result.Status = status
	}
	return result, nil
}

func readExactAlertTargetFenceTx(ctx context.Context, tx *sql.Tx, deploymentID, hostID, targetID string) (AlertRuntimeTargetFence, error) {
	var result AlertRuntimeTargetFence
	if err := tx.QueryRowContext(ctx, `SELECT id,host_id,local_selector_hash,created_ms FROM targets WHERE deployment_id=? AND host_id=? AND id=? AND retired_ms IS NULL`, deploymentID, hostID, targetID).Scan(&result.TargetID, &result.HostID, &result.LocalSelectorHash, &result.CreatedMS); err != nil {
		return result, err
	}
	var configID, configHash sql.NullString
	var observed sql.NullInt64
	err := tx.QueryRowContext(ctx, `SELECT id,config_hash,observed_ms FROM config_snapshots WHERE deployment_id=? AND host_id=? AND target_id=? ORDER BY observed_ms DESC,id DESC LIMIT 1`, deploymentID, hostID, targetID).Scan(&configID, &configHash, &observed)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return result, err
	}
	result.ConfigID, result.ConfigHash, result.ConfigObservedMS = nullableStringPointer(configID), nullableStringPointer(configHash), nullableInt64Pointer(observed)
	return result, nil
}

func equalAlertHostFence(expected, current AlertRuntimeHostFence) bool {
	return expected.HostID == current.HostID && expected.CreatedMS == current.CreatedMS && expected.SessionGeneration == current.SessionGeneration && equalOptionalString(expected.CollectorBootID, current.CollectorBootID) && reflect.DeepEqual(expected.Status, current.Status)
}

func equalAlertTargetFence(expected, current AlertRuntimeTargetFence) bool {
	return expected.HostID == current.HostID && expected.TargetID == current.TargetID && expected.LocalSelectorHash == current.LocalSelectorHash && expected.CreatedMS == current.CreatedMS && equalOptionalString(expected.ConfigID, current.ConfigID) && equalOptionalString(expected.ConfigHash, current.ConfigHash) && equalOptionalInt64(expected.ConfigObservedMS, current.ConfigObservedMS)
}

func applyAlertEpisodeTx(ctx context.Context, tx *sql.Tx, deploymentID string, write AlertEvaluationWrite) (*AlertReachabilityEpisode, error) {
	episodeWrite := write.Episode
	if episodeWrite == nil || write.Input.Reachability == nil || episodeWrite.ObservedMS != write.EventMS || !equalOptionalBool(episodeWrite.Reachable, write.Input.Reachability.Reachable) || !equalAlertTargetFence(episodeWrite.Target, *write.Fence.Target) {
		return nil, ErrAlertCursorConflict
	}
	current, err := readActiveAlertEpisodeTx(ctx, tx, deploymentID, episodeWrite.Target.HostID, episodeWrite.Target.TargetID)
	if err != nil {
		return nil, err
	}
	if !equalAlertEpisode(episodeWrite.Expected, current) {
		return nil, ErrAlertCursorConflict
	}
	if current == nil {
		if episodeWrite.Target.CreatedMS > math.MaxInt64-AlertStartupGrace.Milliseconds() {
			return nil, ErrAlertCursorConflict
		}
		episodeID, err := domain.NewUUID()
		if err != nil {
			return nil, err
		}
		current = &AlertReachabilityEpisode{HostID: episodeWrite.Target.HostID, TargetID: episodeWrite.Target.TargetID, EpisodeID: episodeID, StartMS: episodeWrite.Target.CreatedMS, StartupDeadlineMS: episodeWrite.Target.CreatedMS + AlertStartupGrace.Milliseconds()}
		if current.StartMS > episodeWrite.ObservedMS {
			return nil, ErrAlertCursorConflict
		}
		if episodeWrite.Reachable != nil && *episodeWrite.Reachable {
			current.EverReachable = true
			current.LastReachableMS = int64Pointer(episodeWrite.ObservedMS)
		}
		current.ExitCount, err = countVerifiedEpisodeExitsTx(ctx, tx, deploymentID, *current, episodeWrite.ObservedMS)
		if err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO reachability_episodes(deployment_id,host_id,target_id,episode_id,start_ms,startup_deadline_ms,last_reachable_ms,ever_reachable,exit_count,ended_ms) VALUES(?,?,?,?,?,?,?,?,?,NULL)`, deploymentID, current.HostID, current.TargetID, current.EpisodeID, current.StartMS, current.StartupDeadlineMS, current.LastReachableMS, boolInt(current.EverReachable), current.ExitCount); err != nil {
			return nil, err
		}
	} else {
		previous := *current
		if episodeWrite.ObservedMS < current.StartMS {
			return nil, ErrAlertCursorConflict
		}
		if episodeWrite.Reachable != nil && *episodeWrite.Reachable {
			current.EverReachable = true
			current.LastReachableMS = int64Pointer(episodeWrite.ObservedMS)
		}
		current.ExitCount, err = countVerifiedEpisodeExitsTx(ctx, tx, deploymentID, *current, episodeWrite.ObservedMS)
		if err != nil {
			return nil, err
		}
		result, err := tx.ExecContext(ctx, `UPDATE reachability_episodes SET last_reachable_ms=?,ever_reachable=?,exit_count=? WHERE deployment_id=? AND host_id=? AND target_id=? AND episode_id=? AND ended_ms IS NULL AND start_ms=? AND startup_deadline_ms=? AND last_reachable_ms IS ? AND ever_reachable=? AND exit_count=?`, current.LastReachableMS, boolInt(current.EverReachable), current.ExitCount, deploymentID, previous.HostID, previous.TargetID, previous.EpisodeID, previous.StartMS, previous.StartupDeadlineMS, previous.LastReachableMS, boolInt(previous.EverReachable), previous.ExitCount)
		if err != nil {
			return nil, err
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return nil, ErrAlertCursorConflict
		}
	}
	graceOpen := episodeWrite.Reachable != nil && !*episodeWrite.Reachable && !current.EverReachable && episodeWrite.ObservedMS < current.StartupDeadlineMS
	if write.Input.Reachability.StartupGraceOpen != graceOpen {
		return nil, ErrAlertCursorConflict
	}
	return current, nil
}

// validateAlertEpisodeObservationTx admits another rule evaluation for a
// target after the first deterministic rule in that evaluation pass has
// already advanced the shared episode. It never mutates episode state.
func validateAlertEpisodeObservationTx(ctx context.Context, tx *sql.Tx, deploymentID string, write AlertEvaluationWrite) error {
	if write.Input.Reachability == nil || write.Fence.Target == nil {
		return ErrAlertCursorConflict
	}
	current, err := readActiveAlertEpisodeTx(ctx, tx, deploymentID, write.Fence.Target.HostID, write.Fence.Target.TargetID)
	if err != nil {
		return err
	}
	if current == nil || write.EventMS < current.StartMS {
		return ErrAlertCursorConflict
	}
	exits, err := countVerifiedEpisodeExitsTx(ctx, tx, deploymentID, *current, write.EventMS)
	if err != nil {
		return err
	}
	if exits != current.ExitCount {
		return ErrAlertCursorConflict
	}
	if write.Input.Reachability.Reachable != nil && *write.Input.Reachability.Reachable && (!current.EverReachable || current.LastReachableMS == nil || *current.LastReachableMS != write.EventMS) {
		return ErrAlertCursorConflict
	}
	graceOpen := write.Input.Reachability.Reachable != nil && !*write.Input.Reachability.Reachable && !current.EverReachable && write.EventMS < current.StartupDeadlineMS
	if write.Input.Reachability.StartupGraceOpen != graceOpen {
		return ErrAlertCursorConflict
	}
	return nil
}

func countVerifiedEpisodeExitsTx(ctx context.Context, tx *sql.Tx, deploymentID string, episode AlertReachabilityEpisode, throughMS int64) (int64, error) {
	var count int64
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM events WHERE deployment_id=? AND host_id=? AND target_id=? AND code='selected_process_exit_verified' AND occurred_start_ms>=? AND occurred_start_ms<=?`, deploymentID, episode.HostID, episode.TargetID, episode.StartMS, throughMS).Scan(&count); err != nil {
		return 0, err
	}
	if count < 0 || count > protocol.MaxUint53 {
		return 0, ErrAlertCursorConflict
	}
	return count, nil
}

func equalAlertEpisode(expected, current *AlertReachabilityEpisode) bool {
	if expected == nil || current == nil {
		return expected == nil && current == nil
	}
	return validAlertEpisode(*expected) && expected.HostID == current.HostID && expected.TargetID == current.TargetID && expected.EpisodeID == current.EpisodeID && expected.StartMS == current.StartMS && expected.StartupDeadlineMS == current.StartupDeadlineMS && equalOptionalInt64(expected.LastReachableMS, current.LastReachableMS) && expected.EverReachable == current.EverReachable && expected.ExitCount == current.ExitCount
}

func equalOptionalBool(left, right *bool) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func equalOptionalString(left, right *string) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func equalOptionalInt64(left, right *int64) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func validAlertEpisode(value AlertReachabilityEpisode) bool {
	return validUUIDText(value.HostID) && validUUIDText(value.TargetID) && validUUIDText(value.EpisodeID) && value.StartMS >= 0 && value.StartupDeadlineMS >= value.StartMS && (value.LastReachableMS == nil || *value.LastReachableMS >= value.StartMS) && value.ExitCount >= 0 && value.ExitCount <= protocol.MaxUint53
}

func boundedIncrement(value int64) (int64, error) {
	if value < 0 || value >= math.MaxInt64 || value >= protocol.MaxUint53 {
		return 0, ErrAlertCursorConflict
	}
	return value + 1, nil
}
