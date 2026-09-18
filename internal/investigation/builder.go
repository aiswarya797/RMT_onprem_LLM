package investigation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/query"
	"rmt.local/monitor/internal/store"
)

const (
	minimumFocusMS = int64(5 * 60 * 1000)
	maximumFocusMS = int64(24 * 60 * 60 * 1000)
)

var ErrInvalidInvestigation = errors.New("invalid investigation window or scope")

type SeriesReader interface {
	Series(context.Context, query.SeriesParameters) (query.Series, error)
}

type FactsReader interface {
	ReadInvestigationFacts(context.Context, string, string, string, int64, int64) (store.InvestigationFacts, error)
}

type Clock interface{ NowUnixMilli() int64 }

type Builder struct {
	series SeriesReader
	facts  FactsReader
	now    func() int64
}

func NewBuilder(series SeriesReader, facts FactsReader, now func() int64) *Builder {
	return &Builder{series: series, facts: facts, now: now}
}

type seriesPair struct {
	metric   string
	baseline query.Series
	focus    query.Series
	baseErr  error
	focusErr error
}

func (b *Builder) Build(ctx context.Context, deploymentID string, scope Scope, focus Window) (Capsule, error) {
	duration := focus.EndMS - focus.StartMS
	if b == nil || b.series == nil || b.facts == nil || b.now == nil || deploymentID == "" || !validScope(scope) || focus.StartMS < duration || duration < minimumFocusMS || duration > maximumFocusMS {
		return Capsule{}, ErrInvalidInvestigation
	}
	baseline := Window{StartMS: focus.StartMS - duration, EndMS: focus.StartMS}
	facts, err := b.facts.ReadInvestigationFacts(ctx, deploymentID, scope.Kind, scope.ID, baseline.StartMS, focus.EndMS)
	if err != nil {
		return Capsule{}, err
	}
	pairs := make([]seriesPair, 0, len(metricsForScope(scope.Kind)))
	for _, metric := range metricsForScope(scope.Kind) {
		pair := seriesPair{metric: metric}
		pair.baseline, pair.baseErr = b.series.Series(ctx, query.SeriesParameters{Scope: scope.ID, Metric: metric, Resolution: query.ResolutionAuto, Start: baseline.StartMS, End: baseline.EndMS})
		pair.focus, pair.focusErr = b.series.Series(ctx, query.SeriesParameters{Scope: scope.ID, Metric: metric, Resolution: query.ResolutionAuto, Start: focus.StartMS, End: focus.EndMS})
		if isFatalSeriesError(pair.baseErr) {
			return Capsule{}, pair.baseErr
		}
		if isFatalSeriesError(pair.focusErr) {
			return Capsule{}, pair.focusErr
		}
		pairs = append(pairs, pair)
	}
	cards := []EvidenceCard{}
	if card := collectionGapCard(scope, focus, pairs); card != nil {
		cards = append(cards, *card)
	}
	if card := verifiedExitCard(scope, focus, facts.Events); card != nil {
		cards = append(cards, *card)
	}
	if card := pressureCard(scope, focus, pairs); card != nil {
		cards = append(cards, *card)
	}
	if card := cpuCard(scope, focus, pairs); card != nil {
		cards = append(cards, *card)
	}
	if card := changeCard(scope, focus, baseline, pairs, facts.Configs, facts.Events, facts.ConfigsTruncated); card != nil {
		cards = append(cards, *card)
	}
	cards = append(cards, evidenceLimitsCard(scope, focus, pairs, facts))
	sort.SliceStable(cards, func(i, j int) bool {
		if cards[i].Priority == cards[j].Priority {
			return cards[i].CardID < cards[j].CardID
		}
		return cards[i].Priority < cards[j].Priority
	})
	collapsed := 0
	if len(cards) > 14 {
		collapsed, cards = len(cards)-14, cards[:14]
	}
	return Capsule{
		SchemaRevision: CapsuleSchemaRevision, CatalogueRevision: CatalogueRevision, GeneratedMS: b.now(), Scope: scope,
		FocusWindow: focus, BaselineWindow: baseline, EvidenceState: "partial", Cards: cards, CollapsedCardCount: collapsed,
	}, nil
}

func metricsForScope(kind string) []string {
	switch kind {
	case "host":
		return []string{"host.cpu.busy_ratio", "host.memory.pressure_level", "host.memory.compressed_bytes", "host.memory.swap_used_bytes", "host.disk.free_bytes"}
	case "runtime":
		return []string{"runtime.reachable"}
	case "model":
		return []string{"runtime.model.loaded", "runtime.model.reported_size_bytes", "runtime.model.reported_size_vram_bytes"}
	case "process":
		return []string{"process.cpu.busy_ratio", "process.physical_footprint_bytes"}
	default:
		return nil
	}
}

func validScope(scope Scope) bool {
	if len(metricsForScope(scope.Kind)) == 0 {
		return false
	}
	if scope.Kind == "process" {
		return len(scope.ID) == 64 && allHex(scope.ID)
	}
	return len(scope.ID) == 36
}

func allHex(value string) bool {
	for _, character := range value {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

func isFatalSeriesError(err error) bool {
	return err != nil && !errors.Is(err, query.ErrUnsupportedMetric) && !errors.Is(err, query.ErrNotFound)
}

func collectionGapCard(scope Scope, focus Window, pairs []seriesPair) *EvidenceCard {
	var coverage *float64
	gaps := []Gap{}
	reasons := []string{}
	links := []SourceLink{}
	sources, definitions := []string{}, []string{}
	for _, pair := range pairs {
		if pair.focusErr != nil {
			reasons = appendUnique(reasons, "metric_not_available")
			continue
		}
		if pair.focus.CoverageRatio != nil && (coverage == nil || *pair.focus.CoverageRatio < *coverage) {
			value := *pair.focus.CoverageRatio
			coverage = &value
		}
		for _, gap := range pair.focus.Gaps {
			gaps = appendGap(gaps, Gap{StartMS: gap.StartMS, EndMS: gap.EndMS, Reason: gap.Reason})
		}
		if pair.focus.SourceID != nil {
			sources = appendUnique(sources, *pair.focus.SourceID)
		}
		if pair.focus.DefinitionRevision != "" {
			definitions = appendUnique(definitions, pair.focus.DefinitionRevision)
		}
		links = append(links, SourceLink{ScopeID: scope.ID, Metric: pair.metric, StartMS: focus.StartMS, EndMS: focus.EndMS})
	}
	if len(gaps) == 0 && coverage != nil && *coverage >= 0.9 && len(reasons) == 0 {
		return nil
	}
	if len(gaps) == 0 && coverage == nil && len(reasons) == 0 {
		return nil
	}
	reasons = appendUnique(reasons, "coverage_below_required")
	observed := "coverage unavailable"
	if coverage != nil {
		observed = fmt.Sprintf("%.0f%% coverage", *coverage*100)
	}
	card := baseCard("EC01", 1, "ec01_collection_gap", scope, focus)
	card.Title, card.Summary, card.Eligibility = "Collection evidence is incomplete", fmt.Sprintf("The selected %s evidence has %s and %d explicit gap(s). Missing evidence does not establish inference failure.", scope.Kind, observed, len(gaps)), "insufficient"
	card.ReasonCodes, card.CoverageRatio, card.Gaps, card.SourceIDs, card.DefinitionRevisions, card.SourceLinks = reasons, coverage, boundedGaps(gaps), sources, definitions, links
	card.NextCheckCode, card.NextCheckLabel = "inspect_collection_source", "Inspect collection status, permissions, sleep or compatibility for this source."
	return &card
}

func verifiedExitCard(scope Scope, focus Window, events []store.InvestigationEvent) *EvidenceCard {
	for _, event := range events {
		if event.Code != "selected_process_exit_verified" {
			continue
		}
		card := baseCard("EC02", 2, "ec02_verified_process_exit", scope, focus)
		card.Title, card.Summary, card.Eligibility = "Selected runtime process exited", fmt.Sprintf("A verified selected-process exit was observed at %d. No failed-check duration is inferred from this event.", event.OccurredStartMS), "eligible"
		card.ReasonCodes = []string{"verified_process_exit"}
		card.ReferencedEventIDs = []string{event.ID}
		card.NextCheckCode, card.NextCheckLabel = "inspect_runtime_process", "Inspect the selected endpoint, process identity and last model or configuration observation."
		return &card
	}
	return nil
}

func pressureCard(scope Scope, focus Window, pairs []seriesPair) *EvidenceCard {
	pair := findPair(pairs, "host.memory.pressure_level")
	if pair == nil || pair.focusErr != nil || !rawPredicateSeries(pair.focus) {
		return nil
	}
	state, start, end, ok := sustainedState(pair.focus, 30_000)
	if !ok {
		return nil
	}
	card := baseCard("EC03", 3, "ec03_memory_pressure", scope, focus)
	card.Title, card.Eligibility = "Memory pressure was elevated", "eligible"
	if state == "critical" {
		card.Summary = fmt.Sprintf("Memory pressure was observed critical at %d. This card does not infer a cause.", start)
	} else {
		card.Summary = fmt.Sprintf("Memory pressure was warning for at least %d seconds. This card does not infer a cause.", (end-start)/1000)
	}
	card.ReasonCodes = []string{"pressure_" + state}
	card.Inputs = []CardInput{pointInput(pair.metric, state, "state", start, pair.focus)}
	copySeriesFacts(&card, pair.focus, pair.metric, focus)
	card.NextCheckCode, card.NextCheckLabel = "inspect_process_footprints", "Inspect same-user process footprints and compare compression and swap observations."
	return &card
}

func cpuCard(scope Scope, focus Window, pairs []seriesPair) *EvidenceCard {
	pair := findPair(pairs, "host.cpu.busy_ratio")
	if pair == nil || pair.focusErr != nil || !rawPredicateSeries(pair.focus) {
		return nil
	}
	start, end, peak, ok := sustainedNumeric(pair.focus, 0.90, 60_000)
	if !ok {
		return nil
	}
	card := baseCard("EC04", 4, "ec04_heavy_cpu", scope, focus)
	card.Title, card.Eligibility = "Host CPU was heavily used", "eligible"
	card.Summary = fmt.Sprintf("CPU used at least 90%% of total host capacity for %d seconds; observed peak %.1f%%. This does not establish a cause.", (end-start)/1000, peak*100)
	card.ReasonCodes = []string{"host_cpu_sustained"}
	card.Inputs = []CardInput{pointInput(pair.metric, peak, "ratio", start, pair.focus)}
	copySeriesFacts(&card, pair.focus, pair.metric, focus)
	card.NextCheckCode, card.NextCheckLabel = "inspect_cpu_consumers", "Inspect the bounded same-user process observations and compare a matching observed request if available."
	return &card
}

func changeCard(scope Scope, focus, baseline Window, pairs []seriesPair, configs []store.InvestigationConfig, events []store.InvestigationEvent, truncated bool) *EvidenceCard {
	card := baseCard("EC05", 5, "ec05_captured_change", scope, focus)
	card.Title, card.Eligibility = "Captured model or configuration changes", "insufficient"
	card.NextCheckCode, card.NextCheckLabel = "inspect_change_capture", "Inspect the captured configuration interval or record a bounded operator-declared change."
	if truncated {
		card.ReasonCodes = append(card.ReasonCodes, "config_history_truncated")
	}
	for _, event := range events {
		if event.Code != "config_change_detected" || event.OccurredStartMS >= focus.EndMS || event.OccurredEndMS < focus.StartMS {
			continue
		}
		var fields struct {
			BeforeConfigID string `json:"before_config_id"`
			AfterConfigID  string `json:"after_config_id"`
			BeforeHash     string `json:"before_hash"`
			AfterHash      string `json:"after_hash"`
		}
		if json.Unmarshal(event.AllowlistedFieldsJSON, &fields) != nil || len(fields.BeforeConfigID) != 36 || len(fields.AfterConfigID) != 36 || len(fields.BeforeHash) != 64 || len(fields.AfterHash) != 64 || fields.BeforeHash == fields.AfterHash {
			continue
		}
		provenance := domain.Provenance{Source: domain.ProvenanceRuntimeAPI, MethodRevision: "bounded_config_snapshot_v1", Verification: domain.VerificationDirectCapture}
		_ = json.Unmarshal(event.ProvenanceJSON, &provenance)
		observed := event.OccurredEndMS
		card.Eligibility = "eligible"
		card.ReasonCodes = append(card.ReasonCodes, "config_hash_changed")
		card.ConfigIDs = []string{fields.BeforeConfigID, fields.AfterConfigID}
		card.ReferencedEventIDs = []string{event.ID}
		card.Summary = fmt.Sprintf("Captured configuration changed from %s to %s; it was detected between %d and %d and the exact change time is not inferred.", shortHash(fields.BeforeHash), shortHash(fields.AfterHash), event.OccurredStartMS, event.OccurredEndMS)
		card.Inputs = []CardInput{
			{Name: "config_hash_before", Value: fields.BeforeHash, Unit: "sha256", ObservedMS: &observed, Quality: domain.QualityRuntimeReported, Provenance: provenance},
			{Name: "config_hash_after", Value: fields.AfterHash, Unit: "sha256", ObservedMS: &observed, Quality: domain.QualityRuntimeReported, Provenance: provenance},
		}
		return &card
	}
	for index := 1; index < len(configs); index++ {
		before, after := configs[index-1], configs[index]
		if before.ConfigHash == after.ConfigHash || after.ObservedMS < focus.StartMS || after.ObservedMS >= focus.EndMS {
			continue
		}
		card.Eligibility = "eligible"
		card.ReasonCodes = append(card.ReasonCodes, "config_hash_changed")
		card.ConfigIDs = []string{before.ID, after.ID}
		card.Summary = fmt.Sprintf("Captured configuration changed from %s to %s; the new value was detected at %d and the exact change time is not inferred.", shortHash(before.ConfigHash), shortHash(after.ConfigHash), after.ObservedMS)
		card.Inputs = []CardInput{configInput("config_hash_before", before), configInput("config_hash_after", after)}
		return &card
	}
	pair := findPair(pairs, "runtime.model.loaded")
	if pair != nil && pair.baseErr == nil && pair.focusErr == nil {
		before, beforeTime, beforeOK := lastBoolean(pair.baseline.Points)
		after, afterTime, afterOK := firstBoolean(pair.focus.Points)
		if beforeOK && afterOK && before != after {
			card.Eligibility = "eligible"
			card.ReasonCodes = append(card.ReasonCodes, "model_load_state_changed")
			card.Summary = fmt.Sprintf("Reported model load state changed from %t at %d to %t at %d. This is runtime-reported state, not proof of request activity.", before, beforeTime, after, afterTime)
			copySeriesFacts(&card, pair.focus, pair.metric, focus)
			return &card
		}
	}
	card.ReasonCodes = append(card.ReasonCodes, "no_matching_change_captured")
	card.Summary = "No matching model or configuration change was captured in the selected focus window. This does not establish that nothing changed."
	_ = baseline
	return &card
}

func evidenceLimitsCard(scope Scope, focus Window, pairs []seriesPair, facts store.InvestigationFacts) EvidenceCard {
	card := baseCard("EC07", 7, "ec07_evidence_limits", scope, focus)
	card.Title, card.Eligibility = "Evidence limits", "insufficient"
	reasons := []string{"passive_request_timing_unavailable", "queue_sensor_unavailable", "gpu_sensor_unavailable"}
	for _, pair := range pairs {
		if pair.baseErr != nil || pair.focusErr != nil || pair.baseline.CoverageRatio == nil || *pair.baseline.CoverageRatio < 0.9 {
			reasons = appendUnique(reasons, "matching_baseline_unavailable")
		}
		if pair.metric == "host.memory.pressure_level" || pair.metric == "host.cpu.busy_ratio" {
			if !rawPredicateSeries(pair.focus) {
				reasons = appendUnique(reasons, "raw_predicate_evidence_unavailable")
			} else if seriesHasPredicateBreak(pair.focus) {
				reasons = appendUnique(reasons, "predicate_continuity_unavailable")
			}
		}
	}
	if facts.ConfigsTruncated {
		reasons = appendUnique(reasons, "config_history_truncated")
	}
	if facts.EventsTruncated {
		reasons = appendUnique(reasons, "event_history_truncated")
	}
	for _, event := range facts.Events {
		if event.Code == "config_transition_unavailable" {
			reasons = appendUnique(reasons, "config_transition_interval_unavailable")
		} else if event.Code == "endpoint_association_unavailable" {
			reasons = appendUnique(reasons, "selected_process_association_unavailable")
		}
	}
	card.ReasonCodes = reasons
	card.Summary = "This evidence cannot establish all inference-performance or causality claims: passive request timing, queue depth and GPU sensors are unavailable, and any additional listed limits remain explicit. No request samples does not mean no inference traffic."
	card.NextCheckCode, card.NextCheckLabel = "collect_reviewed_evidence", "Run one reviewed observed request or repair the named source to establish the missing fact."
	return card
}

func baseCard(id string, priority int, template string, scope Scope, focus Window) EvidenceCard {
	return EvidenceCard{CardID: id, Priority: priority, CopyTemplateID: template, Scope: scope, RequestedWindow: focus, ReasonCodes: []string{}, SourceIDs: []string{}, DefinitionRevisions: []string{}, ConfigIDs: []string{}, Inputs: []CardInput{}, Gaps: []Gap{}, ReferencedEventIDs: []string{}, SourceLinks: []SourceLink{}}
}

func copySeriesFacts(card *EvidenceCard, series query.Series, metric string, window Window) {
	card.CoverageRatio = series.CoverageRatio
	card.EffectiveWindow = queryWindow(series.EffectiveRange)
	if series.SourceID != nil {
		card.SourceIDs = appendUnique(card.SourceIDs, *series.SourceID)
	}
	if series.DefinitionRevision != "" {
		card.DefinitionRevisions = appendUnique(card.DefinitionRevisions, series.DefinitionRevision)
	}
	card.SourceLinks = append(card.SourceLinks, SourceLink{ScopeID: card.Scope.ID, Metric: metric, StartMS: window.StartMS, EndMS: window.EndMS})
}

func pointInput(metric string, value any, unit string, observedMS int64, series query.Series) CardInput {
	quality := domain.QualityMeasured
	method := "unknown"
	if series.MethodRevision != nil {
		method = *series.MethodRevision
	}
	return CardInput{Name: strings.ReplaceAll(metric, ".", "_"), Value: value, Unit: unit, ObservedMS: &observedMS, Quality: quality, Provenance: domain.Provenance{Source: sourceForMetric(metric), MethodRevision: method, Verification: domain.VerificationDirectCapture}}
}

func configInput(name string, config store.InvestigationConfig) CardInput {
	provenance := domain.Provenance{Source: domain.ProvenanceRuntimeAPI, MethodRevision: "bounded_config_snapshot_v1", Verification: domain.VerificationDirectCapture}
	_ = json.Unmarshal(config.ProvenanceJSON, &provenance)
	return CardInput{Name: name, Value: config.ConfigHash, Unit: "sha256", ObservedMS: &config.ObservedMS, Quality: domain.QualityRuntimeReported, Provenance: provenance}
}

func sourceForMetric(metric string) string {
	if strings.HasPrefix(metric, "runtime.") {
		return domain.ProvenanceRuntimeAPI
	}
	return domain.ProvenanceDarwinAPI
}

func findPair(pairs []seriesPair, metric string) *seriesPair {
	for index := range pairs {
		if pairs[index].metric == metric {
			return &pairs[index]
		}
	}
	return nil
}

func rawPredicateSeries(series query.Series) bool {
	return series.ResolutionTier != nil && *series.ResolutionTier == "raw" && series.MethodRevision != nil && *series.MethodRevision != ""
}

func seriesHasPredicateBreak(series query.Series) bool {
	if len(series.Gaps) > 0 {
		return true
	}
	for index := 1; index < len(series.Points); index++ {
		if !sameEpoch(series.Points[index-1].EpochID, series.Points[index].EpochID) {
			return true
		}
	}
	return false
}

func sustainedState(series query.Series, minimumMS int64) (string, int64, int64, bool) {
	sorted := append([]query.SeriesPoint(nil), series.Points...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].TimeMS < sorted[j].TimeMS })
	var state string
	var start, last int64
	var epoch *string
	for _, point := range sorted {
		var current string
		if point.Quality != domain.QualityMeasured || point.MissingReason != nil || json.Unmarshal(point.Value, &current) != nil || (current != "warning" && current != "critical") {
			state = ""
			epoch = nil
			continue
		}
		if current == "critical" {
			return current, point.TimeMS, point.TimeMS, true
		}
		if state != current || point.TimeMS-last > 15_000 || !sameEpoch(epoch, point.EpochID) || gapBetween(series.Gaps, last, point.TimeMS) {
			state, start = current, point.TimeMS
		}
		last, epoch = point.TimeMS, cloneStringPointer(point.EpochID)
		if last-start >= minimumMS {
			return state, start, last, true
		}
	}
	return state, start, last, false
}

func sustainedNumeric(series query.Series, threshold float64, minimumMS int64) (int64, int64, float64, bool) {
	sorted := append([]query.SeriesPoint(nil), series.Points...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].TimeMS < sorted[j].TimeMS })
	var start, last int64
	var peak float64
	active := false
	var epoch *string
	for _, point := range sorted {
		var value float64
		if point.Quality != domain.QualityMeasured || point.MissingReason != nil || json.Unmarshal(point.Value, &value) != nil || value < threshold {
			active = false
			epoch = nil
			continue
		}
		if !active || point.TimeMS-last > 15_000 || !sameEpoch(epoch, point.EpochID) || gapBetween(series.Gaps, last, point.TimeMS) {
			start, peak, active = point.TimeMS, value, true
		}
		last, epoch = point.TimeMS, cloneStringPointer(point.EpochID)
		if value > peak {
			peak = value
		}
		if last-start >= minimumMS {
			return start, last, peak, true
		}
	}
	return start, last, peak, false
}

func sameEpoch(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func cloneStringPointer(value *string) *string {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func gapBetween(gaps []query.Gap, start, end int64) bool {
	if end <= start {
		return false
	}
	for _, gap := range gaps {
		if gap.StartMS < end && gap.EndMS > start {
			return true
		}
	}
	return false
}

func lastBoolean(points []query.SeriesPoint) (bool, int64, bool) {
	for index := len(points) - 1; index >= 0; index-- {
		var value bool
		if points[index].MissingReason == nil && json.Unmarshal(points[index].Value, &value) == nil {
			return value, points[index].TimeMS, true
		}
	}
	return false, 0, false
}

func firstBoolean(points []query.SeriesPoint) (bool, int64, bool) {
	for _, point := range points {
		var value bool
		if point.MissingReason == nil && json.Unmarshal(point.Value, &value) == nil {
			return value, point.TimeMS, true
		}
	}
	return false, 0, false
}

func queryWindow(value *query.Range) *Window {
	if value == nil {
		return nil
	}
	return &Window{StartMS: value.StartMS, EndMS: value.EndMS}
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func appendGap(values []Gap, value Gap) []Gap {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func boundedGaps(values []Gap) []Gap {
	if len(values) > 32 {
		return values[:32]
	}
	return values
}

func shortHash(value string) string {
	if len(value) <= 12 {
		return value
	}
	return value[:12]
}
