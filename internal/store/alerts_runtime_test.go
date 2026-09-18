package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"rmt.local/monitor/internal/alerts"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
)

func TestAlertRuntimePlanFencesStatusTargetConfigAndEpisodeProgress(t *testing.T) {
	setup := newIngestSetup(t)
	ctx := context.Background()
	actor := insertAlertRuntimeAdmin(t, setup)
	now := setup.store.clock.Now().UnixMilli()
	status := protocol.SourceStatus{
		Protocol:           domain.ProtocolVersion,
		DeploymentID:       setup.state.DeploymentID,
		HostID:             testHostID,
		SecurityGeneration: setup.state.DeploymentGeneration,
		SessionGeneration:  setup.session.SessionGeneration,
		CollectorBootID:    testBootID,
		Sequence:           1,
		ObservedWallMS:     now,
		Heartbeat:          "fresh",
		Sources:            []protocol.SourceState{{SourceID: testSourceID, State: "fresh"}},
		LossIntervals:      []protocol.LossInterval{},
	}
	if _, err := setup.store.IngestSourceStatus(ctx, status); err != nil {
		t.Fatal(err)
	}
	configID, _ := domain.NewUUID()
	configHash := strings.Repeat("c", 64)
	if _, err := setup.store.db.Exec(`INSERT INTO config_snapshots(id,deployment_id,host_id,target_id,incarnation_id,config_hash,observed_ms,preceding_observed_ms,fields_json,provenance_json) VALUES(?,?,?,?,NULL,?,?,NULL,'{}','{}')`, configID, setup.state.DeploymentID, testHostID, testTargetID, configHash, now); err != nil {
		t.Fatal(err)
	}
	rule, err := setup.store.CreateRule(ctx, actor, "74000000-0000-4000-8000-000000000001", strings.Repeat("1", 64), fixedRuleDefinition(alerts.RuleOllamaUnreachable, testTargetID, json.RawMessage(`null`), 30_000, 30_000))
	if err != nil {
		t.Fatal(err)
	}
	measureAlertTestCapacity(t, setup.store, actor, now)

	plan, err := setup.store.ReadAlertRuntimePlan(ctx, setup.state.DeploymentID, setup.state.DeploymentGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Rules) != 1 || plan.Rules[0].Rule.ID != rule.ID || len(plan.Hosts) != 1 || len(plan.Targets) != 1 || len(plan.Episodes) != 0 || plan.Monitor.CapacityObservedMS == nil {
		t.Fatalf("plan=%#v", plan)
	}
	host, target := plan.Hosts[0], plan.Targets[0]
	if host.Status == nil || host.Status.Sequence != 1 || host.Status.ObservedMS != now || host.Status.AdmittedMS < 0 || host.Status.PayloadSHA256 == "" || host.Status.Heartbeat != "fresh" || len(host.Status.Sources) != 1 {
		t.Fatalf("host fence=%#v", host)
	}
	if host.CreatedMS <= 0 || host.CreatedMS > now {
		t.Fatalf("host creation fence=%#v", host)
	}
	if target.ConfigID == nil || *target.ConfigID != configID || target.ConfigHash == nil || *target.ConfigHash != configHash || target.ConfigObservedMS == nil || *target.ConfigObservedMS != now {
		t.Fatalf("target fence=%#v", target)
	}
	if _, err := setup.store.ReadAlertRuntimePlan(ctx, setup.state.DeploymentID, "74000000-0000-4000-8000-000000000099"); !errors.Is(err, ErrAdmissionFenced) {
		t.Fatalf("wrong generation err=%v", err)
	}

	reachable := true
	status.Sequence = 2
	if _, err := setup.store.IngestSourceStatus(ctx, status); err != nil {
		t.Fatal(err)
	}
	staleStatus := alertRuntimeTargetWrite(actor, rule, 1, now, host, target, nil, &reachable, false)
	if _, err := setup.store.ApplyAlertEvaluation(ctx, staleStatus); !errors.Is(err, ErrAlertCursorConflict) {
		t.Fatalf("stale status fence err=%v", err)
	}
	plan, err = setup.store.ReadAlertRuntimePlan(ctx, setup.state.DeploymentID, setup.state.DeploymentGeneration)
	if err != nil || plan.Hosts[0].Status == nil || plan.Hosts[0].Status.Sequence != 2 {
		t.Fatalf("refreshed plan=%#v err=%v", plan, err)
	}
	host, target = plan.Hosts[0], plan.Targets[0]
	alteredHost := host
	alteredHost.CreatedMS++
	alteredCreation := alertRuntimeTargetWrite(actor, rule, 1, now, alteredHost, target, nil, &reachable, false)
	if _, err := setup.store.ApplyAlertEvaluation(ctx, alteredCreation); !errors.Is(err, ErrAlertCursorConflict) {
		t.Fatalf("altered host creation fence err=%v", err)
	}
	first := alertRuntimeTargetWrite(actor, rule, 1, now, host, target, nil, &reachable, false)
	if result, err := setup.store.ApplyAlertEvaluation(ctx, first); err != nil || result.Snapshot.State != alerts.StateOK {
		t.Fatalf("first=%#v err=%v", result, err)
	}
	plan, err = setup.store.ReadAlertRuntimePlan(ctx, setup.state.DeploymentID, setup.state.DeploymentGeneration)
	if err != nil || len(plan.Episodes) != 1 || !plan.Episodes[0].EverReachable || plan.Episodes[0].LastReachableMS == nil || *plan.Episodes[0].LastReachableMS != now || plan.Episodes[0].StartupDeadlineMS != target.CreatedMS+AlertStartupGrace.Milliseconds() {
		t.Fatalf("episode plan=%#v err=%v", plan.Episodes, err)
	}
	secondRule, err := setup.store.CreateRule(ctx, actor, "74000000-0000-4000-8000-000000000002", strings.Repeat("4", 64), fixedRuleDefinition(alerts.RuleOllamaUnreachable, testTargetID, json.RawMessage(`null`), 30_000, 30_000))
	if err != nil {
		t.Fatal(err)
	}
	measureAlertTestCapacity(t, setup.store, actor, now)
	coalesced := alertRuntimeTargetWrite(actor, secondRule, 1, now, plan.Hosts[0], plan.Targets[0], nil, &reachable, false)
	coalesced.Episode = nil
	if result, err := setup.store.ApplyAlertEvaluation(ctx, coalesced); err != nil || result.Snapshot.State != alerts.StateOK {
		t.Fatalf("coalesced rule=%#v err=%v", result, err)
	}
	plan, err = setup.store.ReadAlertRuntimePlan(ctx, setup.state.DeploymentID, setup.state.DeploymentGeneration)
	if err != nil || len(plan.Episodes) != 1 || plan.Episodes[0].ExitCount != 0 {
		t.Fatalf("coalesced episode=%#v err=%v", plan.Episodes, err)
	}
	episodeBeforeExit := plan.Episodes[0]
	eventID, _ := domain.NewUUID()
	exitMS := now + 500
	if _, err := setup.store.db.Exec(`INSERT INTO events(id,deployment_id,host_id,target_id,incarnation_id,occurred_start_ms,occurred_end_ms,detected_ms,code,severity,allowlisted_fields_json,source,provenance_json,repeat_count) VALUES(?,?,?,?,NULL,?,?,?,'selected_process_exit_verified','info','{}','collector','{}',1)`, eventID, setup.state.DeploymentID, testHostID, testTargetID, exitMS, exitMS, exitMS); err != nil {
		t.Fatal(err)
	}
	unreachable := false
	second := alertRuntimeTargetWrite(actor, rule, 2, now+1_000, plan.Hosts[0], plan.Targets[0], &episodeBeforeExit, &unreachable, false)
	second.ElapsedMS = 1_000
	if result, err := setup.store.ApplyAlertEvaluation(ctx, second); err != nil || result.Snapshot.State != alerts.StatePending {
		t.Fatalf("second=%#v err=%v", result, err)
	}
	if retry, err := setup.store.ApplyAlertEvaluation(ctx, second); err != nil || !retry.Duplicate {
		t.Fatalf("retry=%#v err=%v", retry, err)
	}
	plan, err = setup.store.ReadAlertRuntimePlan(ctx, setup.state.DeploymentID, setup.state.DeploymentGeneration)
	if err != nil || len(plan.Episodes) != 1 || plan.Episodes[0].ExitCount != 1 {
		t.Fatalf("exit-derived episode=%#v err=%v", plan.Episodes, err)
	}

	newConfigID, _ := domain.NewUUID()
	if _, err := setup.store.db.Exec(`INSERT INTO config_snapshots(id,deployment_id,host_id,target_id,incarnation_id,config_hash,observed_ms,preceding_observed_ms,fields_json,provenance_json) VALUES(?,?,?,?,NULL,?,?,?,'{}','{}')`, newConfigID, setup.state.DeploymentID, testHostID, testTargetID, strings.Repeat("d", 64), now+2_000, now); err != nil {
		t.Fatal(err)
	}
	stale := alertRuntimeTargetWrite(actor, rule, 3, now+2_000, plan.Hosts[0], plan.Targets[0], &plan.Episodes[0], &unreachable, false)
	stale.ElapsedMS = 1_000
	if _, err := setup.store.ApplyAlertEvaluation(ctx, stale); !errors.Is(err, ErrAlertCursorConflict) {
		t.Fatalf("stale target fence err=%v", err)
	}
	latest, err := setup.store.ReadAlertRuntimePlan(ctx, setup.state.DeploymentID, setup.state.DeploymentGeneration)
	if err != nil {
		t.Fatal(err)
	}
	firstRulePlan := alertRuntimeRuleByID(t, latest, rule.ID)
	if firstRulePlan.Cursor == nil || firstRulePlan.Cursor.InputOrdinal != 2 || latest.Episodes[0].ExitCount != 1 {
		t.Fatalf("atomic stale rejection plan=%#v err=%v", latest, err)
	}
}

func TestAlertStatusEvidenceBindsPresentAndNeverObservedStatus(t *testing.T) {
	setup := newIngestSetup(t)
	ctx := context.Background()
	actor := insertAlertRuntimeAdmin(t, setup)
	now := setup.store.clock.Now().UnixMilli()
	status := protocol.SourceStatus{Protocol: domain.ProtocolVersion, DeploymentID: setup.state.DeploymentID, HostID: testHostID, SecurityGeneration: setup.state.DeploymentGeneration, SessionGeneration: setup.session.SessionGeneration, CollectorBootID: testBootID, Sequence: 1, ObservedWallMS: now, Heartbeat: "fresh", Sources: []protocol.SourceState{{SourceID: testSourceID, State: "fresh"}}, LossIntervals: []protocol.LossInterval{}}
	if _, err := setup.store.IngestSourceStatus(ctx, status); err != nil {
		t.Fatal(err)
	}
	rule, err := setup.store.CreateRule(ctx, actor, "74000000-0000-4000-8000-000000000011", strings.Repeat("2", 64), fixedRuleDefinition(alerts.RuleHostNotReporting, testHostID, json.RawMessage(`60000`), 0, 30_000))
	if err != nil {
		t.Fatal(err)
	}
	measureAlertTestCapacity(t, setup.store, actor, now)
	plan, err := setup.store.ReadAlertRuntimePlan(ctx, setup.state.DeploymentID, setup.state.DeploymentGeneration)
	if err != nil || plan.Hosts[0].Status == nil {
		t.Fatalf("plan=%#v err=%v", plan, err)
	}
	write := alertTestWrite(actor, rule, 1, now, alerts.Input{DataState: alerts.DataValid, Heartbeat: &alerts.HeartbeatInput{AgeMS: 60_000}})
	write.Fence.Host = &plan.Hosts[0]
	write.ObservedDwellMS = 60_000
	write.Evidence = alertStatusEvidence(now, 60_000)
	write.Evidence.StatusSample = &AlertStatusSample{HostID: testHostID, CollectorBootID: testBootID, SessionGeneration: setup.session.SessionGeneration, Sequence: plan.Hosts[0].Status.Sequence, PayloadSHA256: plan.Hosts[0].Status.PayloadSHA256, ObservedMS: plan.Hosts[0].Status.ObservedMS, AdmittedMS: plan.Hosts[0].Status.AdmittedMS}
	write.Evidence.StatusSample.PayloadSHA256 = strings.Repeat("f", 64)
	if _, err := setup.store.ApplyAlertEvaluation(ctx, write); !errors.Is(err, ErrAlertInvalid) {
		t.Fatalf("altered status evidence err=%v", err)
	}
	write.Evidence.StatusSample.PayloadSHA256 = plan.Hosts[0].Status.PayloadSHA256
	fired, err := setup.store.ApplyAlertEvaluation(ctx, write)
	if err != nil || fired.IncidentID == nil {
		t.Fatalf("fired=%#v err=%v", fired, err)
	}
	incident, err := setup.store.ReadIncident(ctx, setup.state.DeploymentID, *fired.IncidentID)
	if err != nil {
		t.Fatal(err)
	}
	var capsule AlertTriggerCapsule
	if err := json.Unmarshal(incident.CapsulePayload, &capsule); err != nil || capsule.Evidence.StatusSample == nil || capsule.Evidence.StatusSample.PayloadSHA256 != plan.Hosts[0].Status.PayloadSHA256 || len(capsule.Evidence.SourceSamples) != 0 {
		t.Fatalf("capsule=%#v err=%v", capsule, err)
	}

	missingHost := insertAlertTestHost(t, setup.store, actor)
	missingRule, err := setup.store.CreateRule(ctx, actor, "74000000-0000-4000-8000-000000000012", strings.Repeat("3", 64), fixedRuleDefinition(alerts.RuleHostNotReporting, missingHost, json.RawMessage(`60000`), 0, 30_000))
	if err != nil {
		t.Fatal(err)
	}
	measureAlertTestCapacity(t, setup.store, actor, now)
	plan, err = setup.store.ReadAlertRuntimePlan(ctx, setup.state.DeploymentID, setup.state.DeploymentGeneration)
	if err != nil {
		t.Fatal(err)
	}
	var missingFence AlertRuntimeHostFence
	for _, candidate := range plan.Hosts {
		if candidate.HostID == missingHost {
			missingFence = candidate
		}
	}
	prematureMS := missingFence.CreatedMS + 59_999
	premature := alertTestWrite(actor, missingRule, 1, prematureMS, alerts.Input{DataState: alerts.DataValid, Heartbeat: &alerts.HeartbeatInput{AgeMS: 60_000}})
	premature.Fence.Host = &missingFence
	premature.ObservedDwellMS = 60_000
	premature.Evidence = alertStatusEvidence(prematureMS, 60_000)
	premature.Evidence.StatusAbsence = &AlertStatusAbsence{HostID: missingHost, SessionGeneration: 0, CheckedMS: prematureMS}
	if _, err := setup.store.ApplyAlertEvaluation(ctx, premature); !errors.Is(err, ErrAlertInvalid) {
		t.Fatalf("premature no-status evidence err=%v", err)
	}
	absentMS := missingFence.CreatedMS + 60_000
	absent := alertTestWrite(actor, missingRule, 1, absentMS, alerts.Input{DataState: alerts.DataValid, Heartbeat: &alerts.HeartbeatInput{AgeMS: 60_000}})
	absent.Fence.Host = &missingFence
	absent.ObservedDwellMS = 60_000
	absent.Evidence = alertStatusEvidence(absentMS, 60_000)
	absent.Evidence.StatusAbsence = &AlertStatusAbsence{HostID: missingHost, SessionGeneration: 0, CheckedMS: absentMS}
	if result, err := setup.store.ApplyAlertEvaluation(ctx, absent); err != nil || result.IncidentID == nil {
		t.Fatalf("absence result=%#v err=%v", result, err)
	}
}

func insertAlertRuntimeAdmin(t *testing.T, setup ingestSetup) SessionRecord {
	t.Helper()
	userID, _ := domain.NewUUID()
	now := setup.store.clock.Now().UnixMilli()
	if _, err := setup.store.db.Exec(`INSERT INTO users(id,deployment_id,name,argon2_hash,role,disabled,trust_generation,historical_restored,version,created_ms,updated_ms) VALUES(?,?,?,'00000000000000000000000000000000','admin',0,?,0,1,?,?)`, userID, setup.state.DeploymentID, "alert-runtime-admin", setup.state.DeploymentGeneration, now, now); err != nil {
		t.Fatal(err)
	}
	return SessionRecord{User: domain.User{ID: userID, Revision: 1, Name: "alert-runtime-admin", Role: "admin", TrustGeneration: setup.state.DeploymentGeneration}, DeploymentID: setup.state.DeploymentID, Generation: setup.state.DeploymentGeneration, ExpiresMS: now + int64(time.Hour/time.Millisecond)}
}

func alertRuntimeTargetWrite(actor SessionRecord, rule RuleRecord, ordinal, eventMS int64, host AlertRuntimeHostFence, target AlertRuntimeTargetFence, expected *AlertReachabilityEpisode, reachable *bool, startupGrace bool) AlertEvaluationWrite {
	write := alertTestWrite(actor, rule, ordinal, eventMS, alerts.Input{DataState: alerts.DataValid, Reachability: &alerts.ReachabilityInput{CollectorFresh: true, Reachable: reachable, StartupGraceOpen: startupGrace}})
	write.Fence = AlertEvaluationFence{Host: &host, Target: &target}
	write.Episode = &AlertReachabilityEpisodeWrite{Target: target, Expected: expected, ObservedMS: eventMS, Reachable: reachable}
	return write
}

func alertStatusEvidence(observedMS int64, ageMS int64) *AlertCapsuleEvidence {
	value := float64(ageMS)
	return &AlertCapsuleEvidence{MetricID: "collector.heartbeat_age_ms", Unit: "milliseconds", WindowStartMS: observedMS - 1, WindowEndMS: observedMS + 1, ObservedMS: observedMS, Quality: string(domain.QualityMeasured), NumberValue: &value, SourceSamples: []AlertSourceSample{}, SourceSampleCount: 0, RequestSampleIDs: []string{}, RequestSampleCount: 0, DefinitionRevision: domain.RegistryRevision, MethodRevision: "source-status-v1", Gaps: []AlertEvidenceGap{}, UnavailableReasons: []string{}}
}

func alertRuntimeRuleByID(t *testing.T, plan AlertRuntimePlan, ruleID string) AlertRuntimeRulePlan {
	t.Helper()
	for _, rule := range plan.Rules {
		if rule.Rule.ID == ruleID {
			return rule
		}
	}
	t.Fatalf("rule %s absent from plan %#v", ruleID, plan.Rules)
	return AlertRuntimeRulePlan{}
}
