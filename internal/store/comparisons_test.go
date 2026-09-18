package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"rmt.local/monitor/internal/domain"
)

type comparisonFixture struct {
	setup      ingestSetup
	clock      *testClock
	admin      SessionRecord
	configID   string
	configHash string
	modelHash  string
	imports    int
}

func newComparisonFixture(t *testing.T) *comparisonFixture {
	t.Helper()
	setup := newIngestSetup(t)
	clock := &testClock{now: time.Now().UTC().Truncate(time.Second)}
	setup.store.clock = clock
	ctx := context.Background()
	now := clock.Now().UnixMilli()
	adminID := "10000000-0000-4000-8000-000000000011"
	if _, err := setup.store.db.Exec(`INSERT INTO users(id,deployment_id,name,argon2_hash,role,disabled,trust_generation,historical_restored,version,created_ms,updated_ms) VALUES(?,?,?,'00000000000000000000000000000000','admin',0,?,0,1,?,?)`, adminID, setup.state.DeploymentID, "comparison-admin", setup.state.DeploymentGeneration, now, now); err != nil {
		t.Fatal(err)
	}
	model := setup.inventory.Models[0]
	if model.Digest == nil {
		t.Fatal("comparison fixture model has no digest")
	}
	configHash := inventoryModelConfigHash(model)
	configID := "10000000-0000-4000-8000-000000000012"
	if _, err := setup.store.db.Exec(`INSERT INTO config_snapshots(id,deployment_id,host_id,target_id,incarnation_id,config_hash,observed_ms,preceding_observed_ms,fields_json,provenance_json) VALUES(?,?,?,?,NULL,?,?,NULL,'{}','{}')`, configID, setup.state.DeploymentID, testHostID, testTargetID, configHash, now); err != nil {
		t.Fatal(err)
	}
	if _, err := setup.store.MeasureAndRecordCapacity(ctx, setup.state.DeploymentID, now, ExternalCapacityUsage{}); err != nil {
		t.Fatal(err)
	}
	admin := SessionRecord{
		User:         domain.User{ID: adminID, Revision: 1, Name: "comparison-admin", Role: "admin", TrustGeneration: setup.state.DeploymentGeneration},
		DeploymentID: setup.state.DeploymentID,
		Generation:   setup.state.DeploymentGeneration,
		ExpiresMS:    now + int64(time.Hour/time.Millisecond),
	}
	return &comparisonFixture{setup: setup, clock: clock, admin: admin, configID: configID, configHash: configHash, modelHash: *model.Digest}
}

func (f *comparisonFixture) importRun(t *testing.T, runID string, values []float64, statuses []string, mutate func(*RequestPopulationKey)) RequestRun {
	t.Helper()
	if len(values) == 0 {
		t.Fatal("comparison fixture requires at least one sample")
	}
	if len(statuses) == 0 {
		statuses = make([]string, len(values))
		for index := range statuses {
			statuses[index] = "completed"
		}
	}
	if len(statuses) != len(values) {
		t.Fatalf("statuses=%d values=%d", len(statuses), len(values))
	}
	if f.imports > 0 {
		f.clock.now = f.clock.now.Add(time.Minute)
		if _, err := f.setup.store.MeasureAndRecordCapacity(context.Background(), f.setup.state.DeploymentID, f.clock.Now().UnixMilli(), ExternalCapacityUsage{}); err != nil {
			t.Fatal(err)
		}
	}
	f.imports++
	build := "fixture-source-build"
	think := false
	population := RequestPopulationKey{
		TargetID:          testTargetID,
		ModelDigest:       f.modelHash,
		RuntimeVersion:    "0.34.0",
		RuntimeBuild:      &build,
		ConfigRevision:    f.configHash,
		ProfileID:         "short_text_v1",
		ProfileSHA256:     strings.Repeat("b", 64),
		Options:           RequestGenerationOptions{NumCtx: 1024, NumPredict: 64, Think: &think, Stream: true, ColdWarmPolicy: "not_controlled"},
		Concurrency:       1,
		VantageID:         "local_hub",
		ClockMethod:       "monotonic",
		SourceKind:        "imported_test",
		VerificationState: "operator_imported_unverified",
	}
	if mutate != nil {
		mutate(&population)
	}
	samples := make([]RequestSample, len(values))
	completed, failed, cancelled, incomplete := 0, 0, 0, 0
	for index, value := range values {
		status := statuses[index]
		provenance := make(map[string]RequestFieldProvenance, len(requestMetricIDs))
		for _, metric := range requestMetricIDs {
			missing := "field_omitted"
			provenance[metric] = RequestFieldProvenance{Source: "operator_import", Verification: "operator_imported_unverified", MissingReason: &missing}
		}
		sample := RequestSample{
			SchemaVersion:          domain.SchemaVersion,
			SampleID:               fmt.Sprintf("30000000-0000-4000-8000-%012d", f.imports*10000+index+1),
			RunID:                  runID,
			SourceKind:             "imported_test",
			VerificationState:      "operator_imported_unverified",
			ObservationScope:       "explicit_observed_request",
			DeploymentID:           f.setup.state.DeploymentID,
			HostID:                 testHostID,
			SourceID:               testSourceID,
			TargetID:               testTargetID,
			ModelID:                testModelID,
			ConfigSnapshotID:       f.configID,
			PopulationKey:          population,
			RuntimeSourcePinID:     "operator-import-unverified",
			RuntimeOperation:       "generate",
			TerminalRecordObserved: true,
			SubmittedAtMS:          f.clock.Now().UnixMilli() + int64(index),
			OffsetsNS:              RequestOffsets{Submit: "0", End: fmt.Sprintf("%d", int64(value*1e6))},
			TerminalStatus:         status,
			FieldProvenance:        provenance,
			ContentPersistence:     "none",
		}
		switch status {
		case "completed":
			total := value
			httpStatus := 200
			doneReason := "stop"
			sample.HTTPStatus, sample.DoneReason, sample.Metrics.ClientTotalMS = &httpStatus, &doneReason, &total
			provenance["request.client.total_ms"] = RequestFieldProvenance{Source: "operator_import", Verification: "operator_imported_unverified"}
			completed++
		case "failed":
			reason := "runtime_error"
			sample.SafeErrorCategory = &reason
			failed++
		case "cancelled":
			reason := "cancelled"
			sample.SafeErrorCategory = &reason
			cancelled++
		case "incomplete":
			reason := "incomplete_stream"
			sample.SafeErrorCategory = &reason
			incomplete++
		default:
			t.Fatalf("unsupported fixture status %q", status)
		}
		samples[index] = sample
	}
	run := RequestRun{
		SchemaVersion:      domain.SchemaVersion,
		RunID:              runID,
		DeploymentID:       f.setup.state.DeploymentID,
		HostID:             testHostID,
		SourceID:           testSourceID,
		TargetID:           testTargetID,
		ModelID:            testModelID,
		ConfigSnapshotID:   f.configID,
		SourceKind:         "imported_test",
		VerificationState:  "operator_imported_unverified",
		PopulationKey:      population,
		ExpectedCount:      len(samples),
		SubmittedCount:     len(samples),
		CompletedCount:     completed,
		FailedCount:        failed,
		CancelledCount:     cancelled,
		IncompleteCount:    incomplete,
		DecodedSizeBytes:   int64(1024 + len(samples)),
		FinalizationState:  "finalized",
		ContentPersistence: "none",
		Samples:            samples,
	}
	input := ProbeImport{OriginalArtifactSHA256: fmt.Sprintf("%064x", f.imports), NormalizationRevision: "probe-import-1", Run: run}
	key := fmt.Sprintf("50000000-0000-4000-8000-%012d", f.imports)
	job, err := f.setup.store.ImportProbe(context.Background(), f.admin, key, strings.Repeat("d", 64), input)
	if err != nil {
		t.Fatalf("import %s: %v", runID, err)
	}
	if job.State != "succeeded" || job.Result == nil || job.Result.ResourceID != runID || job.Result.ResourceType != "probe_run" {
		t.Fatalf("import job=%#v", job)
	}
	return run
}

func TestProbeImportIsAtomicAndPreservesTerminalProvenance(t *testing.T) {
	f := newComparisonFixture(t)
	runID := "20000000-0000-4000-8000-000000000001"
	f.importRun(t, runID, []float64{10, 20, 30}, []string{"completed", "failed", "cancelled"}, nil)
	stored, err := f.setup.store.ReadImportedRun(context.Background(), f.setup.state.DeploymentID, runID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.RunID != runID || stored.VerificationState != "operator_imported_unverified" || stored.ContentPersistence != "none" || stored.CompletedCount != 1 || stored.FailedCount != 1 || stored.CancelledCount != 1 || len(stored.Samples) != 3 {
		t.Fatalf("stored run=%#v", stored)
	}
	if stored.Samples[0].TerminalStatus != "completed" || stored.Samples[0].Metrics.ClientTotalMS == nil || stored.Samples[1].TerminalStatus != "failed" || stored.Samples[1].SafeErrorCategory == nil || *stored.Samples[1].SafeErrorCategory != "runtime_error" || stored.Samples[2].TerminalStatus != "cancelled" {
		t.Fatalf("stored samples=%#v", stored.Samples)
	}
	if stored.Samples[0].FieldProvenance["request.client.total_ms"].Source != "operator_import" || stored.Samples[0].FieldProvenance["request.client.total_ms"].Verification != "operator_imported_unverified" {
		t.Fatalf("stored provenance=%#v", stored.Samples[0].FieldProvenance)
	}
	var before int
	if err := f.setup.store.db.QueryRow(`SELECT count(*) FROM request_runs WHERE deployment_id=?`, f.setup.state.DeploymentID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	invalid := ProbeImport{OriginalArtifactSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", NormalizationRevision: "probe-import-1", Run: stored}
	invalid.Run.Samples = append([]RequestSample(nil), stored.Samples...)
	invalid.Run.Samples[0].Metrics.ClientTotalMS = comparisonFloatPointer(999)
	if _, err := f.setup.store.ImportProbe(context.Background(), f.admin, "50000000-0000-4000-8000-000000000099", strings.Repeat("e", 64), invalid); !errors.Is(err, ErrProbeImportInvalid) {
		t.Fatalf("invalid import error=%v", err)
	}
	var after int
	if err := f.setup.store.db.QueryRow(`SELECT count(*) FROM request_runs WHERE deployment_id=?`, f.setup.state.DeploymentID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("invalid import changed run count from %d to %d", before, after)
	}
}

func TestDirectProbeContextIsLocalAndDirectCaptureIsIdempotent(t *testing.T) {
	f := newComparisonFixture(t)
	contextValue, err := f.setup.store.ReadDirectProbeContext(context.Background(), testTargetID)
	if err != nil {
		t.Fatal(err)
	}
	if contextValue.DeploymentID != f.setup.state.DeploymentID || contextValue.HostID != testHostID || contextValue.SourceID != testSourceID || contextValue.ConfigSnapshotID != f.configID || len(contextValue.Models) != 1 || contextValue.Models[0].ID != testModelID || contextValue.Models[0].Digest == nil || *contextValue.Models[0].Digest != f.modelHash {
		t.Fatalf("direct context = %#v", contextValue)
	}

	run := f.directRun("21000000-0000-4000-8000-000000000001")
	receipt, err := f.setup.store.RecordDirectProbe(context.Background(), f.admin, "51000000-0000-4000-8000-000000000001", strings.Repeat("1", 64), run)
	if err != nil || receipt.Status != "succeeded" || receipt.RunID == nil || *receipt.RunID != run.RunID || receipt.SubmittedCount != 1 {
		t.Fatalf("direct receipt = %#v err=%v", receipt, err)
	}
	retried, err := f.setup.store.RecordDirectProbe(context.Background(), f.admin, "51000000-0000-4000-8000-000000000001", strings.Repeat("1", 64), run)
	if err != nil || retried.Status != receipt.Status || retried.RunID == nil || *retried.RunID != run.RunID {
		t.Fatalf("direct retry = %#v err=%v", retried, err)
	}
	if _, err := f.setup.store.RecordDirectProbe(context.Background(), f.admin, "51000000-0000-4000-8000-000000000001", strings.Repeat("2", 64), run); !errors.Is(err, ErrProbeRunConflict) {
		t.Fatalf("changed direct retry error = %v", err)
	}
	stored, err := f.setup.store.ReadImportedRun(context.Background(), f.setup.state.DeploymentID, run.RunID)
	if err != nil || stored.SourceKind != "deliberate_probe" || stored.VerificationState != "direct_capture" || len(stored.Samples) != 1 || stored.Samples[0].RuntimeSourcePinID != "ollama-0.12.10-source" || stored.Samples[0].FieldProvenance["request.client.total_ms"].Source != "client_monotonic" || stored.Samples[0].FieldProvenance["request.runtime.total_duration_ms"].Source != "ollama_terminal" {
		t.Fatalf("stored direct run = %#v err=%v", stored, err)
	}
}

func (f *comparisonFixture) directRun(runID string) RequestRun {
	think := false
	temperature := float64(0)
	seed := int64(7)
	build := "fixture-direct-build"
	population := RequestPopulationKey{
		TargetID: testTargetID, ModelDigest: f.modelHash, RuntimeVersion: "0.12.10", RuntimeBuild: &build,
		ConfigRevision: f.configHash, ProfileID: "short_text_v1", ProfileSHA256: strings.Repeat("b", 64),
		Options:     RequestGenerationOptions{NumCtx: 1024, NumPredict: 64, Temperature: &temperature, Seed: &seed, Think: &think, Stream: true, ColdWarmPolicy: "cold_model_unloaded"},
		Concurrency: 1, VantageID: "mac-local", ClockMethod: "monotonic", SourceKind: "deliberate_probe", VerificationState: "direct_capture",
	}
	firstByte, firstContent, total := 2.0, 4.0, 10.0
	runtimeTotal, runtimeLoad, runtimePrompt, runtimeEval := 9.0, 1.0, 2.0, 6.0
	promptTokens, outputTokens := int64(8), int64(4)
	httpStatus := 200
	doneReason := "stop"
	end := "10000000"
	provenance := make(map[string]RequestFieldProvenance, len(requestMetricIDs))
	for _, metric := range requestMetricIDs {
		source := "client_monotonic"
		if strings.HasPrefix(metric, "request.runtime.") {
			source = "ollama_terminal"
		}
		provenance[metric] = RequestFieldProvenance{Source: source, Verification: "direct_capture"}
	}
	sample := RequestSample{
		SchemaVersion: domain.SchemaVersion, SampleID: "22000000-0000-4000-8000-000000000001", RunID: runID, SourceKind: "deliberate_probe", VerificationState: "direct_capture", ObservationScope: "explicit_observed_request",
		DeploymentID: f.setup.state.DeploymentID, HostID: testHostID, SourceID: testSourceID, TargetID: testTargetID, ModelID: testModelID, ConfigSnapshotID: f.configID,
		PopulationKey: population, RuntimeSourcePinID: "ollama-0.12.10-source", RuntimeOperation: "generate", TerminalRecordObserved: true,
		SubmittedAtMS: f.clock.Now().UnixMilli(), OffsetsNS: RequestOffsets{Submit: "0", Headers: stringPointer("1000000"), FirstByte: stringPointer("2000000"), FirstContent: stringPointer("4000000"), End: end},
		HTTPStatus: &httpStatus, TerminalStatus: "completed", DoneReason: &doneReason, Metrics: RequestMetrics{ClientFirstByteMS: &firstByte, ClientFirstContentMS: &firstContent, ClientTotalMS: &total, RuntimeTotalDurationMS: &runtimeTotal, RuntimeLoadDurationMS: &runtimeLoad, RuntimePromptEvalMS: &runtimePrompt, RuntimeEvalMS: &runtimeEval, RuntimePromptTokens: &promptTokens, RuntimeOutputTokens: &outputTokens}, FieldProvenance: provenance, ContentPersistence: "none",
	}
	return RequestRun{
		SchemaVersion: domain.SchemaVersion, RunID: runID, DeploymentID: f.setup.state.DeploymentID, HostID: testHostID, SourceID: testSourceID, TargetID: testTargetID, ModelID: testModelID, ConfigSnapshotID: f.configID,
		SourceKind: "deliberate_probe", VerificationState: "direct_capture", PopulationKey: population, ExpectedCount: 1, SubmittedCount: 1, CompletedCount: 1, DecodedSizeBytes: 1024, FinalizationState: "finalized", ContentPersistence: "none", Samples: []RequestSample{sample},
	}
}

func TestComparisonPreviewUsesExactMedianP95AndExplainsPopulationMismatch(t *testing.T) {
	f := newComparisonFixture(t)
	beforeID := "20000000-0000-4000-8000-000000000002"
	afterID := "20000000-0000-4000-8000-000000000003"
	f.importRun(t, beforeID, []float64{10, 20, 30}, nil, nil)
	f.importRun(t, afterID, []float64{20, 30, 40}, nil, nil)
	request := RequestComparison{ComparisonKind: "request_run", ScopeID: testTargetID, MetricID: "request.client.total_ms", BeforeRunID: beforeID, AfterRunID: afterID}
	result, err := f.setup.store.PreviewComparison(context.Background(), f.admin, request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "observed_change_similar_recorded_conditions" || len(result.BlockedReasons) != 0 || result.Before.Summary == nil || result.After.Summary == nil || result.Before.Summary.Median != 20 || result.After.Summary.Median != 30 || result.Before.Summary.P95 != nil || result.After.Summary.P95 != nil {
		t.Fatalf("small comparison=%#v", result)
	}

	p95BeforeID := "20000000-0000-4000-8000-000000000004"
	p95AfterID := "20000000-0000-4000-8000-000000000005"
	valuesBefore, valuesAfter := make([]float64, 100), make([]float64, 100)
	for index := range valuesBefore {
		valuesBefore[index] = float64(index + 1)
		valuesAfter[index] = float64(index + 2)
	}
	f.importRun(t, p95BeforeID, valuesBefore, nil, nil)
	f.importRun(t, p95AfterID, valuesAfter, nil, nil)
	p95, err := f.setup.store.PreviewComparison(context.Background(), f.admin, RequestComparison{ComparisonKind: "request_run", ScopeID: testTargetID, MetricID: "request.client.total_ms", BeforeRunID: p95BeforeID, AfterRunID: p95AfterID})
	if err != nil || p95.Before.Summary == nil || p95.After.Summary == nil || p95.Before.Summary.P95 == nil || p95.After.Summary.P95 == nil || *p95.Before.Summary.P95 != 95 || *p95.After.Summary.P95 != 96 {
		t.Fatalf("p95 comparison=%#v err=%v", p95, err)
	}

	mismatchID := "20000000-0000-4000-8000-000000000006"
	f.importRun(t, mismatchID, []float64{25, 35, 45}, nil, func(population *RequestPopulationKey) { population.RuntimeVersion = "0.35.0" })
	blocked, err := f.setup.store.PreviewComparison(context.Background(), f.admin, RequestComparison{ComparisonKind: "request_run", ScopeID: testTargetID, MetricID: "request.client.total_ms", BeforeRunID: beforeID, AfterRunID: mismatchID})
	if err != nil {
		t.Fatal(err)
	}
	if blocked.Status != "insufficient_evidence" || !containsString(blocked.BlockedReasons, "runtime_version_change") || len(blocked.BlockedReasons) == 0 {
		t.Fatalf("blocked comparison=%#v", blocked)
	}
}

func TestComparisonSaveAttachReopenAndViewerReadAreDurable(t *testing.T) {
	f := newComparisonFixture(t)
	beforeID := "20000000-0000-4000-8000-000000000007"
	afterID := "20000000-0000-4000-8000-000000000008"
	f.importRun(t, beforeID, []float64{10, 20, 30}, nil, nil)
	f.importRun(t, afterID, []float64{20, 30, 40}, nil, nil)
	request := RequestComparison{ComparisonKind: "request_run", ScopeID: testTargetID, MetricID: "request.client.total_ms", BeforeRunID: beforeID, AfterRunID: afterID}
	job, err := f.setup.store.SaveComparison(context.Background(), f.admin, "60000000-0000-4000-8000-000000000001", strings.Repeat("f", 64), request)
	if err != nil || job.State != "succeeded" || job.Result == nil {
		t.Fatalf("save job=%#v err=%v", job, err)
	}
	comparisonID := job.Result.ResourceID
	reopened, err := f.setup.store.ReadComparison(context.Background(), f.admin, comparisonID)
	if err != nil || !reopened.Persisted || reopened.ResultID == nil || *reopened.ResultID != comparisonID || reopened.ClaimScope != "explicit_observed_requests_only_no_causal_claim" {
		t.Fatalf("reopened=%#v err=%v", reopened, err)
	}
	incidentID := "70000000-0000-4000-8000-000000000001"
	now := f.clock.Now().UnixMilli()
	if _, err := f.setup.store.db.Exec(`INSERT INTO incidents(id,deployment_id,target_scope_json,title,origin,start_ms,end_ms,alert_instance_id,workflow_state,owner_user_id,snapshot_id,evidence_expiry_reason,version,created_ms,updated_ms) VALUES(?,?,?,?, 'manual',?,?,NULL,'open',NULL,NULL,NULL,1,?,?)`, incidentID, f.setup.state.DeploymentID, fmt.Sprintf(`{"kind":"host","id":"%s"}`, testHostID), "comparison fixture", now-1000, now, now, now); err != nil {
		t.Fatal(err)
	}
	if err := f.setup.store.AttachComparison(context.Background(), f.admin, incidentID, comparisonID, "60000000-0000-4000-8000-000000000002", strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err := f.setup.store.AttachComparison(context.Background(), f.admin, incidentID, comparisonID, "60000000-0000-4000-8000-000000000002", strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	refs, err := f.setup.store.ListIncidentComparisons(context.Background(), f.admin, incidentID)
	if err != nil || len(refs) != 1 || refs[0].ComparisonID != comparisonID || refs[0].BeforeRunID != beforeID || refs[0].AfterRunID != afterID {
		t.Fatalf("comparison refs=%#v err=%v", refs, err)
	}

	viewerID := "10000000-0000-4000-8000-000000000013"
	if _, err := f.setup.store.db.Exec(`INSERT INTO users(id,deployment_id,name,argon2_hash,role,disabled,trust_generation,historical_restored,version,created_ms,updated_ms) VALUES(?,?,?,'00000000000000000000000000000000','viewer',0,?,0,1,?,?)`, viewerID, f.setup.state.DeploymentID, "comparison-viewer", f.setup.state.DeploymentGeneration, now, now); err != nil {
		t.Fatal(err)
	}
	viewer := f.admin
	viewer.User = domain.User{ID: viewerID, Revision: 1, Name: "comparison-viewer", Role: "viewer", TrustGeneration: f.setup.state.DeploymentGeneration}
	if _, err := f.setup.store.ReadComparison(context.Background(), viewer, comparisonID); err != nil {
		t.Fatalf("viewer read error=%v", err)
	}
	if _, err := f.setup.store.SaveComparison(context.Background(), viewer, "60000000-0000-4000-8000-000000000003", strings.Repeat("b", 64), request); !errors.Is(err, ErrOwnershipMismatch) {
		t.Fatalf("viewer save error=%v", err)
	}
}

func comparisonFloatPointer(value float64) *float64 { return &value }

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
