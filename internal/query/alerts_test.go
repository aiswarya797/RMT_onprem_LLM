package query

import (
	"encoding/json"
	"testing"
	"time"

	"rmt.local/monitor/internal/alertruntime"
	"rmt.local/monitor/internal/alerts"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
	"rmt.local/monitor/internal/store"
)

const (
	alertTargetID = "12000000-0000-4000-8000-000000000001"
	alertRuleID   = "12000000-0000-4000-8000-000000000002"
)

func TestHeartbeatAndSourceMissingUseExactDurableStatusEvidence(t *testing.T) {
	now := int64(1_800_000_000_000)
	lastSuccess := now - 1_000
	host := alertHostFence(now-61_000, now, []protocol.SourceState{{SourceID: querySourceID, State: "fresh", LastSuccessMS: &lastSuccess}})
	target := store.AlertRuntimeTargetFence{HostID: queryHostID, TargetID: alertTargetID, LocalSelectorHash: hashText("c"), CreatedMS: now - 600_000}
	snapshot := alertSnapshot()
	snapshot.inventory.Targets = []store.QueryTarget{{ID: alertTargetID, HostID: queryHostID}}
	snapshot.inventory.Sources = append(snapshot.inventory.Sources, store.QuerySource{ID: "12000000-0000-4000-8000-000000000003", HostID: queryHostID, Kind: "runtime", TargetID: pointer(alertTargetID)})
	plan := alertPlan(host, target,
		alertRule(alerts.RuleHostNotReporting, queryHostID),
		alertRule(alerts.RuleSourceMissing, alertTargetID),
	)
	writes, err := buildAlertWrites(plan, snapshot, alertCycle(now, 5*time.Second, false))
	if err != nil || len(writes) != 2 {
		t.Fatalf("writes=%#v err=%v", writes, err)
	}
	heartbeat := writes[0]
	if heartbeat.Input.Heartbeat == nil || heartbeat.Input.Heartbeat.AgeMS != 61_000 || heartbeat.Evidence == nil || heartbeat.Evidence.StatusSample == nil || heartbeat.Evidence.SourceSampleCount != 0 || heartbeat.Evidence.StatusSample.PayloadSHA256 != hashText("d") {
		t.Fatalf("heartbeat=%#v", heartbeat)
	}
	if heartbeat.Input.DataState != alerts.DataValid {
		t.Fatalf("delayed durable status looked fresh/unknown: %#v", heartbeat.Input)
	}
	staleSource := writes[1]
	if staleSource.Input.DataState != alerts.DataStale || staleSource.Input.Source == nil || staleSource.Input.Source.HostFresh || staleSource.Evidence != nil {
		t.Fatalf("delayed status refreshed source incorrectly: %#v", staleSource)
	}

	freshHost := alertHostFence(now, now, []protocol.SourceState{{SourceID: querySourceID, State: "fresh", LastSuccessMS: &lastSuccess}})
	freshPlan := alertPlan(freshHost, target, alertRule(alerts.RuleSourceMissing, alertTargetID))
	freshWrites, err := buildAlertWrites(freshPlan, snapshot, alertCycle(now, 5*time.Second, false))
	if err != nil || len(freshWrites) != 1 {
		t.Fatalf("fresh writes=%#v err=%v", freshWrites, err)
	}
	missing := freshWrites[0]
	if missing.Input.Source == nil || missing.Input.Source.Available == nil || *missing.Input.Source.Available || !missing.Input.Source.HostFresh || missing.Evidence == nil || missing.Evidence.StatusSample == nil || missing.Evidence.SourceSampleCount != 0 {
		t.Fatalf("source missing=%#v", missing)
	}
}

func TestNeverObservedHeartbeatUsesPersistedHostAgeAndExactAbsence(t *testing.T) {
	now := int64(1_800_000_000_000)
	host := store.AlertRuntimeHostFence{HostID: queryHostID, CreatedMS: now - 60_000, SessionGeneration: 0}
	plan := alertPlan(host, store.AlertRuntimeTargetFence{}, alertRule(alerts.RuleHostNotReporting, queryHostID))
	writes, err := buildAlertWrites(plan, alertSnapshot(), alertCycle(now, 0, true))
	if err != nil || len(writes) != 1 {
		t.Fatalf("writes=%#v err=%v", writes, err)
	}
	write := writes[0]
	if write.Input.DataState != alerts.DataValid || write.Input.Heartbeat == nil || write.Input.Heartbeat.AgeMS != 60_000 || write.ObservedDwellMS != 60_000 {
		t.Fatalf("heartbeat input=%#v dwell=%d", write.Input, write.ObservedDwellMS)
	}
	if write.Evidence == nil || write.Evidence.StatusSample != nil || write.Evidence.StatusAbsence == nil || write.Evidence.StatusAbsence.HostID != queryHostID || write.Evidence.StatusAbsence.SessionGeneration != 0 || write.Evidence.StatusAbsence.CollectorBootID != nil || write.Evidence.StatusAbsence.CheckedMS != now || write.Evidence.SourceSampleCount != 0 {
		t.Fatalf("heartbeat absence=%#v", write.Evidence)
	}
	if write.Evidence.WindowStartMS != now-60_000 || write.Evidence.WindowEndMS != now+1 || write.Evidence.ObservedMS != now {
		t.Fatalf("heartbeat window=%#v", write.Evidence)
	}
}

func TestHeavyCPUUsesOnlyCompatibleCurrentFramesAndExactDwellSamples(t *testing.T) {
	now := int64(1_800_000_000_000)
	lastSuccess := now
	host := alertHostFence(now, now, []protocol.SourceState{{SourceID: querySourceID, State: "fresh", LastSuccessMS: &lastSuccess}})
	snapshot := alertSnapshot()
	frames := make([]protocol.CollectorFrame, 0, 14)
	rows := make([]store.QueryFrame, 0, 14)
	for index := int64(0); index <= 12; index++ {
		observed := now - index*5_000
		frames = append(frames, protocol.CollectorFrame{Gauges: map[string]protocol.MetricValue{"host.cpu.busy_ratio": metricValue(json.RawMessage(`0.95`), "darwin-host-cpu-candidate-1")}})
		rows = append(rows, store.QueryFrame{HostID: queryHostID, SourceID: querySourceID, CollectorBootID: queryBootID, DeliveryMode: "current", Sequence: 100 - index, OriginalWallMS: observed})
	}
	// A newer replay value cannot replace the current-session input.
	frames = append([]protocol.CollectorFrame{{Gauges: map[string]protocol.MetricValue{"host.cpu.busy_ratio": metricValue(json.RawMessage(`0.10`), "darwin-host-cpu-candidate-1")}}}, frames...)
	rows = append([]store.QueryFrame{{HostID: queryHostID, SourceID: querySourceID, CollectorBootID: queryBootID, DeliveryMode: "replay", Sequence: 999, OriginalWallMS: now + 1}}, rows...)
	snapshot.frames[querySourceID], snapshot.rows[querySourceID] = frames, rows
	rule := alertRule(alerts.RuleHeavyCPU, queryHostID)
	rule.Snapshot = &alerts.Snapshot{DwellMS: 55_000, State: alerts.StatePending}
	plan := alertPlan(host, store.AlertRuntimeTargetFence{}, rule)
	writes, err := buildAlertWrites(plan, snapshot, alertCycle(now, 5*time.Second, false))
	if err != nil || len(writes) != 1 {
		t.Fatalf("writes=%#v err=%v", writes, err)
	}
	write := writes[0]
	if write.Input.CPU == nil || write.Input.CPU.BusyRatio == nil || *write.Input.CPU.BusyRatio != 0.95 || write.ObservedDwellMS != 60_000 || write.Evidence == nil || write.Evidence.SourceSampleCount != 13 || write.Evidence.SourceSamplesTruncated || len(write.Evidence.Gaps) != 0 {
		t.Fatalf("cpu write=%#v", write)
	}
}

func TestReachabilityGraceIsEpisodeScopedAndEpisodeUpdateIsCoalesced(t *testing.T) {
	now := int64(1_800_000_000_000)
	lastSuccess := now
	runtimeSourceID := "12000000-0000-4000-8000-000000000003"
	host := alertHostFence(now, now, []protocol.SourceState{{SourceID: runtimeSourceID, State: "fresh", LastSuccessMS: &lastSuccess}})
	target := store.AlertRuntimeTargetFence{HostID: queryHostID, TargetID: alertTargetID, LocalSelectorHash: hashText("c"), CreatedMS: now - 60_000}
	snapshot := alertSnapshot()
	snapshot.inventory.Targets = []store.QueryTarget{{ID: alertTargetID, HostID: queryHostID}}
	snapshot.inventory.Sources = []store.QuerySource{{ID: runtimeSourceID, HostID: queryHostID, Kind: "runtime", TargetID: pointer(alertTargetID)}}
	snapshot.frames[runtimeSourceID] = []protocol.CollectorFrame{{Gauges: map[string]protocol.MetricValue{"runtime.reachable": {Value: json.RawMessage(`false`), Quality: domain.QualityRuntimeReported, Provenance: domain.Provenance{Source: domain.ProvenanceRuntimeAPI, MethodRevision: "ollama-0.34.0-bounded-read-v1", Verification: domain.VerificationDirectCapture}}}}}
	snapshot.rows[runtimeSourceID] = []store.QueryFrame{{HostID: queryHostID, SourceID: runtimeSourceID, CollectorBootID: queryBootID, DeliveryMode: "current", Sequence: 1, OriginalWallMS: now}}
	first := alertRule(alerts.RuleOllamaUnreachable, alertTargetID)
	second := alertRule(alerts.RuleOllamaUnreachable, alertTargetID)
	second.Rule.ID = "12000000-0000-4000-8000-000000000004"
	plan := alertPlan(host, target, first, second)
	writes, err := buildAlertWrites(plan, snapshot, alertCycle(now, 5*time.Second, false))
	if err != nil || len(writes) != 2 {
		t.Fatalf("writes=%#v err=%v", writes, err)
	}
	if writes[0].Input.Reachability == nil || !writes[0].Input.Reachability.StartupGraceOpen || writes[0].Episode == nil || writes[1].Episode != nil {
		t.Fatalf("coalesced reachability writes=%#v", writes)
	}
	if writes[0].Input.Reachability.Reachable == nil || *writes[0].Input.Reachability.Reachable {
		t.Fatalf("reachability input=%#v", writes[0].Input)
	}
}

func TestObservedRequestRuleRemainsUnknownWithoutExactPopulationQuery(t *testing.T) {
	now := int64(1_800_000_000_000)
	host := alertHostFence(now, now, nil)
	target := store.AlertRuntimeTargetFence{HostID: queryHostID, TargetID: alertTargetID, LocalSelectorHash: hashText("c"), CreatedMS: now - 60_000}
	plan := alertPlan(host, target, alertRule(alerts.RuleObservedRequestDuration, alertTargetID))
	writes, err := buildAlertWrites(plan, alertSnapshot(), alertCycle(now, 5*time.Second, false))
	if err != nil || len(writes) != 1 || writes[0].Input.DataState != alerts.DataUnknown || writes[0].Input.Request != nil || writes[0].Evidence != nil {
		t.Fatalf("request write=%#v err=%v", writes, err)
	}
}

func alertPlan(host store.AlertRuntimeHostFence, target store.AlertRuntimeTargetFence, rules ...store.AlertRuntimeRulePlan) store.AlertRuntimePlan {
	plan := store.AlertRuntimePlan{DeploymentID: "12000000-0000-4000-8000-000000000010", DeploymentGeneration: "12000000-0000-4000-8000-000000000011", Rules: rules, Hosts: []store.AlertRuntimeHostFence{host}, Targets: []store.AlertRuntimeTargetFence{}, Episodes: []store.AlertReachabilityEpisode{}}
	if target.TargetID != "" {
		plan.Targets = append(plan.Targets, target)
	}
	return plan
}

func alertRule(ruleType alerts.RuleType, scope string) store.AlertRuntimeRulePlan {
	return store.AlertRuntimeRulePlan{Rule: store.RuleRecord{ID: alertRuleID, Revision: 1, Definition: store.RuleDefinition{EvaluatorType: ruleType, ScopeID: scope, Enabled: true}}}
}

func alertHostFence(admitted, observed int64, sources []protocol.SourceState) store.AlertRuntimeHostFence {
	return store.AlertRuntimeHostFence{HostID: queryHostID, CreatedMS: admitted - 60_000, SessionGeneration: 1, CollectorBootID: pointer(queryBootID), Status: &store.AlertRuntimeStatusFence{Sequence: 1, PayloadSHA256: hashText("d"), ObservedMS: observed, AdmittedMS: admitted, Heartbeat: "fresh", Sources: sources}}
}

func alertSnapshot() liveSnapshot {
	return liveSnapshot{inventory: store.QueryInventory{Deployment: domain.DeploymentState{DeploymentID: "12000000-0000-4000-8000-000000000010", DeploymentGeneration: "12000000-0000-4000-8000-000000000011"}, Hosts: []store.QueryHost{{ID: queryHostID}}, Sources: []store.QuerySource{{ID: querySourceID, HostID: queryHostID, Kind: "host"}}}, statuses: map[string]protocol.SourceStatus{}, frames: map[string][]protocol.CollectorFrame{}, rows: map[string][]store.QueryFrame{}}
}

func alertCycle(now int64, elapsed time.Duration, restarted bool) alertruntime.Cycle {
	return alertruntime.Cycle{EventTime: time.UnixMilli(now), Elapsed: elapsed, Lag: 5 * time.Second, Restarted: restarted}
}

func hashText(value string) string {
	result := ""
	for len(result) < 64 {
		result += value
	}
	return result[:64]
}
