package investigation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/query"
	"rmt.local/monitor/internal/store"
)

const (
	testDeploymentID = "10000000-0000-4000-8000-000000000001"
	testScopeID      = "10000000-0000-4000-8000-000000000002"
	testFocusStart   = int64(1_800_000_300_000)
	testFocusEnd     = int64(1_800_000_600_000)
)

type fixtureSeriesReader struct {
	calls []query.SeriesParameters
	read  func(query.SeriesParameters) (query.Series, error)
}

func (reader *fixtureSeriesReader) Series(_ context.Context, parameters query.SeriesParameters) (query.Series, error) {
	reader.calls = append(reader.calls, parameters)
	return reader.read(parameters)
}

type fixtureFactsReader struct{ facts store.InvestigationFacts }

func (reader fixtureFactsReader) ReadInvestigationFacts(_ context.Context, _, _, _ string, _, _ int64) (store.InvestigationFacts, error) {
	return reader.facts, nil
}

func TestBuilderFreezesEqualBaselineAndEmitsOnlySupportedEvidence(t *testing.T) {
	coverage := 1.0
	sourceID := "10000000-0000-4000-8000-000000000003"
	method := "fixture-v1"
	resolution := "raw"
	reader := &fixtureSeriesReader{read: func(parameters query.SeriesParameters) (query.Series, error) {
		series := query.Series{Metric: parameters.Metric, DefinitionRevision: "mac-ollama-1", SourceID: &sourceID, MethodRevision: &method, ResolutionTier: &resolution, CoverageRatio: &coverage, Points: []query.SeriesPoint{}, Gaps: []query.Gap{}}
		if parameters.Start == testFocusStart {
			switch parameters.Metric {
			case "host.cpu.busy_ratio":
				series.Points = numericPoints(testFocusStart, []float64{0.91, 0.92, 0.93, 0.94, 0.95})
			case "host.memory.pressure_level":
				series.Points = stringPoints(testFocusStart, []string{"warning", "warning", "warning"})
			}
		}
		return series, nil
	}}
	eventID := "10000000-0000-4000-8000-000000000004"
	facts := store.InvestigationFacts{HostID: testScopeID, Configs: []store.InvestigationConfig{}, Events: []store.InvestigationEvent{{ID: eventID, Code: "unverified_exit_guess", OccurredStartMS: testFocusStart + 1}}}
	builder := NewBuilder(reader, fixtureFactsReader{facts: facts}, func() int64 { return testFocusEnd + 1 })
	capsule, err := builder.Build(context.Background(), testDeploymentID, Scope{Kind: "host", ID: testScopeID}, Window{StartMS: testFocusStart, EndMS: testFocusEnd})
	if err != nil {
		t.Fatal(err)
	}
	if capsule.FocusWindow != (Window{StartMS: testFocusStart, EndMS: testFocusEnd}) || capsule.BaselineWindow != (Window{StartMS: testFocusStart - 300_000, EndMS: testFocusStart}) {
		t.Fatalf("windows focus=%#v baseline=%#v", capsule.FocusWindow, capsule.BaselineWindow)
	}
	if len(reader.calls) != 10 {
		t.Fatalf("series calls=%d", len(reader.calls))
	}
	for _, call := range reader.calls {
		if call.Resolution != query.ResolutionAuto || (call.Start != capsule.FocusWindow.StartMS && call.Start != capsule.BaselineWindow.StartMS) {
			t.Fatalf("unexpected bounded series call=%#v", call)
		}
	}
	if cardByID(capsule.Cards, "EC03") == nil || cardByID(capsule.Cards, "EC04") == nil || cardByID(capsule.Cards, "EC07") == nil {
		t.Fatalf("missing supported cards=%#v", cardIDs(capsule.Cards))
	}
	if cardByID(capsule.Cards, "EC02") != nil || cardByID(capsule.Cards, "EC06") != nil {
		t.Fatalf("fabricated exit or request card=%#v", cardIDs(capsule.Cards))
	}
	limits := cardByID(capsule.Cards, "EC07")
	for _, expected := range []string{"passive_request_timing_unavailable", "queue_sensor_unavailable", "gpu_sensor_unavailable"} {
		if !contains(limits.ReasonCodes, expected) {
			t.Fatalf("EC07 reasons=%v", limits.ReasonCodes)
		}
	}
	payload, digest, err := capsule.Marshal()
	if err != nil || len(payload) > MaxCapsuleBytes || len(digest) != 64 || strings.Contains(string(payload), "prompt") {
		t.Fatalf("capsule bytes=%d digest=%q err=%v", len(payload), digest, err)
	}
}

func TestBuilderRequiresVerifiedExitAndLabelsAbsentChangeCapture(t *testing.T) {
	coverage := 1.0
	reader := &fixtureSeriesReader{read: func(parameters query.SeriesParameters) (query.Series, error) {
		if parameters.Metric != "runtime.reachable" {
			return query.Series{}, query.ErrUnsupportedMetric
		}
		return query.Series{Metric: parameters.Metric, CoverageRatio: &coverage, Points: []query.SeriesPoint{}, Gaps: []query.Gap{}}, nil
	}}
	eventID := "10000000-0000-4000-8000-000000000005"
	facts := store.InvestigationFacts{HostID: testScopeID, Configs: []store.InvestigationConfig{}, Events: []store.InvestigationEvent{{ID: eventID, Code: "selected_process_exit_verified", OccurredStartMS: testFocusStart + 1, OccurredEndMS: testFocusStart + 1}, {ID: "10000000-0000-4000-8000-000000000006", Code: "endpoint_association_unavailable", OccurredStartMS: testFocusStart + 2, OccurredEndMS: testFocusStart + 3}}}
	capsule, err := NewBuilder(reader, fixtureFactsReader{facts: facts}, func() int64 { return testFocusEnd }).Build(context.Background(), testDeploymentID, Scope{Kind: "runtime", ID: testScopeID}, Window{StartMS: testFocusStart, EndMS: testFocusEnd})
	if err != nil {
		t.Fatal(err)
	}
	exit := cardByID(capsule.Cards, "EC02")
	if exit == nil || len(exit.ReferencedEventIDs) != 1 || exit.ReferencedEventIDs[0] != eventID || !strings.Contains(exit.Summary, "No failed-check duration is inferred") {
		t.Fatalf("verified exit=%#v", exit)
	}
	change := cardByID(capsule.Cards, "EC05")
	if change == nil || change.Eligibility != "insufficient" || !contains(change.ReasonCodes, "no_matching_change_captured") || !strings.Contains(change.Summary, "does not establish that nothing changed") {
		t.Fatalf("change card=%#v", change)
	}
	limits := cardByID(capsule.Cards, "EC07")
	if limits == nil || !contains(limits.ReasonCodes, "selected_process_association_unavailable") {
		t.Fatalf("association limit=%#v", limits)
	}
}

func TestBuilderUsesVerifiedConfigTransitionIntervalForEC05(t *testing.T) {
	reader := &fixtureSeriesReader{read: func(parameters query.SeriesParameters) (query.Series, error) {
		return query.Series{Metric: parameters.Metric, Points: []query.SeriesPoint{}, Gaps: []query.Gap{}}, nil
	}}
	beforeID := "10000000-0000-4000-8000-000000000021"
	afterID := "10000000-0000-4000-8000-000000000022"
	eventID := "10000000-0000-4000-8000-000000000023"
	beforeHash, afterHash := strings.Repeat("a", 64), strings.Repeat("b", 64)
	fields, _ := json.Marshal(map[string]string{"before_config_id": beforeID, "after_config_id": afterID, "before_hash": beforeHash, "after_hash": afterHash})
	provenance, _ := json.Marshal(domain.Provenance{Source: domain.ProvenanceRuntimeAPI, MethodRevision: "ollama-0.34.0-bounded-read-v1", Verification: domain.VerificationDirectCapture})
	transitionStart, transitionEnd := testFocusStart+15_000, testFocusStart+45_000
	facts := store.InvestigationFacts{HostID: testScopeID, Events: []store.InvestigationEvent{{
		ID: eventID, Code: "config_change_detected", Severity: "info", OccurredStartMS: transitionStart, OccurredEndMS: transitionEnd,
		Source: domain.ProvenanceRuntimeAPI, AllowlistedFieldsJSON: fields, ProvenanceJSON: provenance,
	}}}
	capsule, err := NewBuilder(reader, fixtureFactsReader{facts: facts}, func() int64 { return testFocusEnd }).Build(context.Background(), testDeploymentID, Scope{Kind: "runtime", ID: testScopeID}, Window{StartMS: testFocusStart, EndMS: testFocusEnd})
	if err != nil {
		t.Fatal(err)
	}
	change := cardByID(capsule.Cards, "EC05")
	if change == nil || change.Eligibility != "eligible" || len(change.ConfigIDs) != 2 || change.ConfigIDs[0] != beforeID || change.ConfigIDs[1] != afterID || len(change.ReferencedEventIDs) != 1 || change.ReferencedEventIDs[0] != eventID {
		t.Fatalf("config change card=%#v", change)
	}
	if !strings.Contains(change.Summary, fmt.Sprintf("between %d and %d", transitionStart, transitionEnd)) || !strings.Contains(change.Summary, "exact change time is not inferred") {
		t.Fatalf("config change summary=%q", change.Summary)
	}
}

func TestBuilderRejectsFatalSeriesErrorsAndInvalidWindows(t *testing.T) {
	reader := &fixtureSeriesReader{read: func(query.SeriesParameters) (query.Series, error) {
		return query.Series{}, errors.New("storage unavailable")
	}}
	builder := NewBuilder(reader, fixtureFactsReader{facts: store.InvestigationFacts{HostID: testScopeID}}, func() int64 { return testFocusEnd })
	if _, err := builder.Build(context.Background(), testDeploymentID, Scope{Kind: "host", ID: testScopeID}, Window{StartMS: testFocusStart, EndMS: testFocusStart + 1}); !errors.Is(err, ErrInvalidInvestigation) {
		t.Fatalf("short window err=%v", err)
	}
	if _, err := builder.Build(context.Background(), testDeploymentID, Scope{Kind: "host", ID: testScopeID}, Window{StartMS: testFocusStart, EndMS: testFocusEnd}); err == nil || errors.Is(err, ErrInvalidInvestigation) {
		t.Fatalf("fatal series err=%v", err)
	}
}

func TestPressureCriticalRollupDoesNotInventExactObservationTime(t *testing.T) {
	coverage := 1.0
	sourceID, method, minute := "10000000-0000-4000-8000-000000000003", "fixture-v1", store.RollupMinute
	reader := &fixtureSeriesReader{read: func(parameters query.SeriesParameters) (query.Series, error) {
		series := query.Series{Metric: parameters.Metric, DefinitionRevision: "mac-ollama-1", SourceID: &sourceID, MethodRevision: &method, ResolutionTier: &minute, CoverageRatio: &coverage, Points: []query.SeriesPoint{}, Gaps: []query.Gap{}}
		if parameters.Start == testFocusStart && parameters.Metric == "host.memory.pressure_level" {
			value, _ := json.Marshal("critical")
			series.Points = []query.SeriesPoint{{TimeMS: testFocusStart, Value: value, Quality: domain.QualityDerived}}
		}
		return series, nil
	}}
	capsule, err := NewBuilder(reader, fixtureFactsReader{facts: store.InvestigationFacts{HostID: testScopeID}}, func() int64 { return testFocusEnd }).Build(context.Background(), testDeploymentID, Scope{Kind: "host", ID: testScopeID}, Window{StartMS: testFocusStart, EndMS: testFocusEnd})
	if err != nil {
		t.Fatal(err)
	}
	if cardByID(capsule.Cards, "EC03") != nil {
		t.Fatalf("rollup fabricated EC03 cards=%v", cardIDs(capsule.Cards))
	}
	limits := cardByID(capsule.Cards, "EC07")
	if limits == nil || !contains(limits.ReasonCodes, "raw_predicate_evidence_unavailable") {
		t.Fatalf("rollup limits=%#v", limits)
	}
}

func TestSustainedPredicatesBreakAcrossEpochsAndExplicitGaps(t *testing.T) {
	coverage := 1.0
	sourceID, method, resolution := "10000000-0000-4000-8000-000000000003", "fixture-v1", "raw"
	epochA, epochB := "10000000-0000-4000-8000-000000000011", "10000000-0000-4000-8000-000000000012"
	reader := &fixtureSeriesReader{read: func(parameters query.SeriesParameters) (query.Series, error) {
		series := query.Series{Metric: parameters.Metric, DefinitionRevision: "mac-ollama-1", SourceID: &sourceID, MethodRevision: &method, ResolutionTier: &resolution, CoverageRatio: &coverage, Points: []query.SeriesPoint{}, Gaps: []query.Gap{}}
		if parameters.Start != testFocusStart {
			return series, nil
		}
		switch parameters.Metric {
		case "host.memory.pressure_level":
			series.Points = stringPoints(testFocusStart, []string{"warning", "warning", "warning"})
			series.Points[0].EpochID, series.Points[1].EpochID, series.Points[2].EpochID = &epochA, &epochA, &epochB
		case "host.cpu.busy_ratio":
			series.Points = numericPoints(testFocusStart, []float64{0.91, 0.92, 0.93, 0.94, 0.95})
			for index := range series.Points {
				series.Points[index].EpochID = &epochA
			}
			series.Gaps = []query.Gap{{StartMS: testFocusStart + 29_000, EndMS: testFocusStart + 31_000, Reason: domain.MissingCollectionGap}}
		}
		return series, nil
	}}
	capsule, err := NewBuilder(reader, fixtureFactsReader{facts: store.InvestigationFacts{HostID: testScopeID}}, func() int64 { return testFocusEnd }).Build(context.Background(), testDeploymentID, Scope{Kind: "host", ID: testScopeID}, Window{StartMS: testFocusStart, EndMS: testFocusEnd})
	if err != nil {
		t.Fatal(err)
	}
	if cardByID(capsule.Cards, "EC03") != nil || cardByID(capsule.Cards, "EC04") != nil {
		t.Fatalf("continuity break fabricated sustained card=%v", cardIDs(capsule.Cards))
	}
	limits := cardByID(capsule.Cards, "EC07")
	if limits == nil || !contains(limits.ReasonCodes, "predicate_continuity_unavailable") {
		t.Fatalf("continuity limits=%#v", limits)
	}
}

func numericPoints(start int64, values []float64) []query.SeriesPoint {
	points := make([]query.SeriesPoint, 0, len(values))
	for index, value := range values {
		encoded, _ := json.Marshal(value)
		points = append(points, query.SeriesPoint{TimeMS: start + int64(index)*15_000, Value: encoded, Quality: domain.QualityMeasured})
	}
	return points
}

func stringPoints(start int64, values []string) []query.SeriesPoint {
	points := make([]query.SeriesPoint, 0, len(values))
	for index, value := range values {
		encoded, _ := json.Marshal(value)
		points = append(points, query.SeriesPoint{TimeMS: start + int64(index)*15_000, Value: encoded, Quality: domain.QualityMeasured})
	}
	return points
}

func cardByID(cards []EvidenceCard, id string) *EvidenceCard {
	for index := range cards {
		if cards[index].CardID == id {
			return &cards[index]
		}
	}
	return nil
}

func cardIDs(cards []EvidenceCard) []string {
	ids := make([]string, 0, len(cards))
	for _, card := range cards {
		ids = append(ids, card.CardID)
	}
	return ids
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
