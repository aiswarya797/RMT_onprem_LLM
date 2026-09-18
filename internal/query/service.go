package query

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
	"rmt.local/monitor/internal/store"
)

var (
	ErrInvalidQuery          = errors.New("invalid query")
	ErrNotFound              = errors.New("resource not found")
	ErrUnsupportedMetric     = errors.New("metric is not available for this scope")
	ErrUnsupportedResolution = errors.New("resolution tier is not available")
	ErrPointLimit            = errors.New("query would exceed point limit")
)

const (
	liveFrameLookback = 24 * time.Hour
	liveFrameLimit    = 512
)

type Service struct {
	store *store.Store
	clock domain.Clock
}

func New(st *store.Store, clock domain.Clock) *Service {
	if clock == nil {
		clock = domain.RealClock{}
	}
	return &Service{store: st, clock: clock}
}

type liveSnapshot struct {
	inventory store.QueryInventory
	statuses  map[string]protocol.SourceStatus
	frames    map[string][]protocol.CollectorFrame
	rows      map[string][]store.QueryFrame
}

func (s *Service) Overview(ctx context.Context) (Overview, error) {
	now := s.clock.Now().UnixMilli()
	snapshot, err := s.live(ctx, now)
	if err != nil {
		return Overview{}, err
	}
	hosts := s.hosts(snapshot, now)
	targets := s.targets(snapshot, hosts, now)
	capabilities := collectOverviewMissing(hosts, targets)
	population := "absent"
	if snapshot.inventory.ObservedRequestCount > 0 {
		population = "present"
	}
	return Overview{
		GeneratedMS: now, DeploymentState: snapshot.inventory.Deployment, State: overviewState(hosts, targets),
		HostCount: activeHostCount(snapshot.inventory.Hosts), TargetCount: activeTargetCount(snapshot.inventory.Targets), OpenIncidentCount: snapshot.inventory.OpenIncidentCount,
		ObservedRequestPopulation: population, HistoryAvailable: snapshot.inventory.HistoryFrameCount > 0,
		Hosts: hosts, Targets: targets, CapabilitiesMissing: capabilities,
	}, nil
}

func (s *Service) MonitorHealth(ctx context.Context) (MonitorHealth, error) {
	now := s.clock.Now().UnixMilli()
	inventory, err := s.store.ReadQueryInventory(ctx)
	if err != nil {
		return MonitorHealth{}, err
	}
	hosts, err := s.Hosts(ctx)
	if err != nil {
		return MonitorHealth{}, err
	}
	capacity, err := s.store.ReadCapacityState(ctx, inventory.Deployment.DeploymentID, now)
	if err != nil {
		return MonitorHealth{}, err
	}
	gaps, err := s.store.CoverageGapCount(ctx, inventory.Deployment.DeploymentID)
	if err != nil {
		return MonitorHealth{}, err
	}
	clockWarnings := 0
	for _, host := range hosts {
		for _, missing := range host.CapabilitiesMissing {
			if missing.Reason == domain.MissingAlignmentUnavailable {
				clockWarnings++
				break
			}
		}
	}
	return MonitorHealth{GeneratedMS: now, StorageState: capacity.State, CollectorStates: hosts, Gaps: gaps, ClockWarnings: clockWarnings}, nil
}

func (s *Service) StorageForecast(ctx context.Context) (StorageForecast, error) {
	now := s.clock.Now().UnixMilli()
	inventory, err := s.store.ReadQueryInventory(ctx)
	if err != nil {
		return StorageForecast{}, err
	}
	capacity, err := s.store.ReadCapacityState(ctx, inventory.Deployment.DeploymentID, now)
	if err != nil {
		return StorageForecast{}, err
	}
	return StorageForecast{PhysicalBytes: capacity.LivePhysicalBytes, ReservedBytes: capacity.LiveReservedBytes, LiveLimitBytes: capacity.LiveLimitBytes, State: capacity.State, EstimatedDaysRemaining: nil}, nil
}

func (s *Service) Hosts(ctx context.Context) ([]Host, error) {
	now := s.clock.Now().UnixMilli()
	snapshot, err := s.live(ctx, now)
	if err != nil {
		return nil, err
	}
	return s.hosts(snapshot, now), nil
}

func (s *Service) Host(ctx context.Context, id string) (Host, error) {
	hosts, err := s.Hosts(ctx)
	if err != nil {
		return Host{}, err
	}
	for _, host := range hosts {
		if host.ID == id {
			return host, nil
		}
	}
	return Host{}, ErrNotFound
}

func (s *Service) Targets(ctx context.Context) ([]Target, error) {
	now := s.clock.Now().UnixMilli()
	snapshot, err := s.live(ctx, now)
	if err != nil {
		return nil, err
	}
	hosts := s.hosts(snapshot, now)
	return s.targets(snapshot, hosts, now), nil
}

func (s *Service) Target(ctx context.Context, id string) (Target, error) {
	targets, err := s.Targets(ctx)
	if err != nil {
		return Target{}, err
	}
	for _, target := range targets {
		if target.ID == id {
			return target, nil
		}
	}
	return Target{}, ErrNotFound
}

func (s *Service) live(ctx context.Context, now int64) (liveSnapshot, error) {
	inventory, err := s.store.ReadQueryInventory(ctx)
	if err != nil {
		return liveSnapshot{}, err
	}
	result := liveSnapshot{inventory: inventory, statuses: make(map[string]protocol.SourceStatus), frames: make(map[string][]protocol.CollectorFrame), rows: make(map[string][]store.QueryFrame)}
	statuses, err := s.store.ReadCurrentSourceStatuses(ctx, inventory.Deployment.DeploymentID)
	if err != nil {
		return result, err
	}
	for _, row := range statuses {
		status, err := protocol.DecodeSourceStatus(strings.NewReader(row.PayloadJSON))
		if err != nil {
			return result, fmt.Errorf("decode current source status: %w", err)
		}
		result.statuses[row.HostID] = status
	}
	codec, err := store.NewFrameCodecV1()
	if err != nil {
		return result, err
	}
	defer codec.Close()
	for _, source := range inventory.Sources {
		if source.RetiredMS != nil {
			continue
		}
		rows, err := s.store.ReadQueryFrames(ctx, store.QueryFrameFilter{
			DeploymentID: inventory.Deployment.DeploymentID, HostID: source.HostID, SourceID: source.ID,
			StartMS: max(0, now-liveFrameLookback.Milliseconds()), EndMS: now + 1, CurrentOnly: true, Descending: true, Limit: liveFrameLimit,
		})
		if err != nil {
			return result, err
		}
		for _, row := range rows {
			if err := row.ValidateCodec(); err != nil {
				return result, err
			}
			frame, err := codec.Decode(row.Payload)
			if err != nil {
				return result, fmt.Errorf("decode persisted current frame: %w", err)
			}
			result.frames[source.ID] = append(result.frames[source.ID], frame)
		}
		result.rows[source.ID] = rows
	}
	return result, nil
}

func (s *Service) hosts(snapshot liveSnapshot, now int64) []Host {
	result := make([]Host, 0, len(snapshot.inventory.Hosts))
	for _, stored := range snapshot.inventory.Hosts {
		state := "active"
		if stored.RetiredMS != nil {
			state = "retired"
		} else if stored.CurrentSessionGeneration == 0 || stored.LastBootID == nil {
			state = "not_reporting"
		}
		status, hasStatus := snapshot.statuses[stored.ID]
		heartbeat, heartbeatAge := optionalTimeAndAge(hasStatus, status.ObservedWallMS, now)
		hostSourceIDs := activeSourceIDs(snapshot.inventory.Sources, stored.ID, "host")
		sourceState := hostSourceState(stored, status, hasStatus, now, hostSourceIDs)
		if sourceState == SourceDisconnected && state == "active" {
			state = "not_reporting"
		}
		host := Host{
			ID: stored.ID, DisplayName: stored.DisplayName, State: state, SourceState: sourceState,
			Local:            stored.Local,
			CollectorVersion: stored.CollectorVersion, CurrentSessionGeneration: stored.CurrentSessionGeneration, UpdatedMS: stored.UpdatedMS,
			HeartbeatMS: heartbeat, HeartbeatAgeMS: heartbeatAge, Metrics: []MetricReading{}, NetworkObservations: []domain.NetworkObservation{}, Processes: []domain.ProcessObservation{}, CapabilitiesMissing: []domain.MissingCapability{},
		}
		for _, source := range snapshot.inventory.Sources {
			if source.HostID != stored.ID || source.Kind != "host" || source.RetiredMS != nil {
				continue
			}
			host.Metrics = latestGaugeReadings(snapshot.frames[source.ID], snapshot.rows[source.ID], hostMetricIDs, source.ID, stored.ID, now)
			host.NetworkObservedMS, host.NetworkAgeMS, host.NetworkObservations = latestNetwork(snapshot.frames[source.ID], snapshot.rows[source.ID], now)
			host.ProcessObservedMS, host.ProcessAgeMS, host.ProcessSummary, host.Processes = latestProcess(snapshot.frames[source.ID], snapshot.rows[source.ID], now)
			host.CapabilitiesMissing = latestCapabilities(snapshot.frames[source.ID])
			break
		}
		if len(host.Metrics) == 0 {
			for _, id := range hostMetricIDs {
				host.Metrics = append(host.Metrics, unavailableReading(id, stored.ID, nil, domain.MissingPopulationNotObserved, now))
			}
		}
		if host.ProcessSummary != nil && host.ProcessSummary.Coverage == "partial" && host.SourceState == SourceFresh {
			host.SourceState = SourcePartial
		}
		if host.SourceState == SourceFresh && hostObservationPartial(host) {
			host.SourceState = SourcePartial
		}
		result = append(result, host)
	}
	return result
}

func (s *Service) targets(snapshot liveSnapshot, hosts []Host, now int64) []Target {
	result := make([]Target, 0, len(snapshot.inventory.Targets))
	for _, stored := range snapshot.inventory.Targets {
		target := Target{
			ID: stored.ID, HostID: stored.HostID, DisplayName: stored.DisplayName, AdapterID: stored.AdapterID,
			AssociationState: "declared_unverified", Retired: stored.RetiredMS != nil, SourceState: SourceNotObserved,
			Reachable:   unavailableReading("runtime.reachable", stored.ID, nil, domain.MissingPopulationNotObserved, now),
			ModelsState: SourceNotObserved, Models: []Model{}, CapabilitiesMissing: []domain.MissingCapability{},
		}
		for _, host := range hosts {
			if host.ID == stored.HostID {
				target.HostLocal = host.Local
				break
			}
		}
		for _, source := range snapshot.inventory.Sources {
			if source.TargetID == nil || *source.TargetID != stored.ID || source.Kind != "runtime" || source.RetiredMS != nil {
				continue
			}
			status, hasStatus := snapshot.statuses[source.HostID]
			target.SourceState = sourceStateFor(source, status, hasStatus, now)
			readings := latestGaugeReadings(snapshot.frames[source.ID], snapshot.rows[source.ID], []string{"runtime.reachable"}, source.ID, stored.ID, now)
			if len(readings) == 1 {
				target.Reachable = readings[0]
			}
			target.ModelsState, target.ModelsObservedMS, target.ModelsAgeMS, target.Models = latestModels(snapshot.frames[source.ID], snapshot.rows[source.ID], now)
			target.CapabilitiesMissing = latestCapabilities(snapshot.frames[source.ID])
			break
		}
		target.ModelsState, target.ModelsObservedMS, target.ModelsAgeMS, target.Models = mergeInventoryModels(target, snapshot.inventory.Models, now)
		for _, host := range hosts {
			if host.ID != stored.HostID {
				continue
			}
			if host.SourceState == SourceDisconnected {
				target.SourceState = SourceDisconnected
			}
			for _, process := range host.Processes {
				if process.TargetID == nil || *process.TargetID != stored.ID {
					continue
				}
				switch process.AssociationQuality {
				case domain.AssociationVerified:
					target.AssociationState = "verified"
				case domain.AssociationDeclaredUnverified:
					target.AssociationState = "declared_unverified"
				}
			}
		}
		result = append(result, target)
	}
	return result
}

var hostMetricIDs = []string{"host.cpu.busy_ratio", "host.memory.pressure_level", "host.memory.compressed_bytes", "host.memory.swap_used_bytes", "host.disk.free_bytes"}

func latestGaugeReadings(frames []protocol.CollectorFrame, rows []store.QueryFrame, ids []string, sourceID, scopeID string, now int64) []MetricReading {
	seen := make(map[string]MetricReading, len(ids))
	wanted := make(map[string]bool, len(ids))
	for _, id := range ids {
		wanted[id] = true
	}
	for index, frame := range frames {
		if index >= len(rows) {
			break
		}
		for id, value := range frame.Gauges {
			if !wanted[id] {
				continue
			}
			if _, exists := seen[id]; exists {
				continue
			}
			timeMS := rows[index].ObservationMS()
			age := ageMS(now, timeMS)
			seen[id] = MetricReading{Metric: id, Unit: metricDefinitions[id].unit, ScopeID: scopeID, SourceID: pointer(sourceID), ObservedMS: &timeMS, AgeMS: &age, Value: cloneRaw(value.Value), Quality: value.Quality, MissingReason: value.MissingReason, MethodRevision: value.Provenance.MethodRevision, Provenance: value.Provenance}
		}
	}
	result := make([]MetricReading, 0, len(ids))
	for _, id := range ids {
		if value, ok := seen[id]; ok {
			result = append(result, value)
		} else {
			result = append(result, unavailableReading(id, scopeID, pointer(sourceID), domain.MissingPopulationNotObserved, now))
		}
	}
	return result
}

func latestNetwork(frames []protocol.CollectorFrame, rows []store.QueryFrame, now int64) (*int64, *int64, []domain.NetworkObservation) {
	for index, frame := range frames {
		if index >= len(rows) || !isNetworkComponent(frame) {
			continue
		}
		timeMS := rows[index].ObservationMS()
		age := ageMS(now, timeMS)
		observations := make([]domain.NetworkObservation, len(frame.NetworkObservations))
		copy(observations, frame.NetworkObservations)
		return &timeMS, &age, observations
	}
	return nil, nil, []domain.NetworkObservation{}
}

func isNetworkComponent(frame protocol.CollectorFrame) bool {
	return frame.Provenance.MethodRevision == "darwin-net-rt-iflist2-ifdata64-candidate-1" || len(frame.NetworkObservations) > 0 || hasNetworkCapability(frame.CapabilitiesMissing)
}

func latestProcess(frames []protocol.CollectorFrame, rows []store.QueryFrame, now int64) (*int64, *int64, *domain.ProcessSummary, []domain.ProcessObservation) {
	for index, frame := range frames {
		if index >= len(rows) {
			break
		}
		if frame.ProcessSummary != nil {
			timeMS := rows[index].ObservationMS()
			age := ageMS(now, timeMS)
			summary := *frame.ProcessSummary
			processes := make([]domain.ProcessObservation, len(frame.ProcessObservations))
			copy(processes, frame.ProcessObservations)
			return &timeMS, &age, &summary, processes
		}
	}
	return nil, nil, nil, []domain.ProcessObservation{}
}

func latestModels(frames []protocol.CollectorFrame, rows []store.QueryFrame, now int64) (SourceState, *int64, *int64, []Model) {
	for index, frame := range frames {
		if index >= len(rows) || !isModelComponent(frame) {
			continue
		}
		timeMS := rows[index].ObservationMS()
		age := ageMS(now, timeMS)
		inventoryIncomplete := false
		for _, missing := range frame.CapabilitiesMissing {
			if missing.ID == "runtime.model.loaded" {
				return SourceUnavailable, &timeMS, &age, []Model{}
			}
			if missing.ID == "runtime.model.digest" || missing.ID == "runtime.model.identity" {
				inventoryIncomplete = true
			}
		}
		models := make([]Model, 0, len(frame.ModelObservations))
		for _, item := range frame.ModelObservations {
			loadState := "reported_not_loaded"
			if item.Loaded {
				loadState = "reported_loaded"
			}
			digest := item.Digest
			models = append(models, Model{ID: item.ModelID, Digest: &digest, Loaded: item.Loaded, LoadState: loadState, ReportedSizeBytes: item.ReportedSizeBytes, ReportedSizeVRAMBytes: item.ReportedSizeVRAMBytes, Provenance: item.Provenance})
		}
		state := SourceFresh
		if inventoryIncomplete && len(models) == 0 {
			state = SourceUnavailable
		} else if inventoryIncomplete {
			state = SourcePartial
		} else if age > int64(45*time.Second/time.Millisecond) {
			state = SourceStale
		}
		return state, &timeMS, &age, models
	}
	return SourceNotObserved, nil, nil, []Model{}
}

// mergeInventoryModels keeps the collector's installed model identities next
// to the separate runtime-loaded observation. Inventory rows are durable
// collector observations; they do not imply that a model is loaded now or is
// actively generating.
func mergeInventoryModels(target Target, inventory []store.QueryModel, now int64) (SourceState, *int64, *int64, []Model) {
	byID := make(map[string]Model)
	for _, model := range target.Models {
		byID[model.ID] = model
	}
	var latest int64
	for _, stored := range inventory {
		if stored.TargetID != target.ID || stored.HostID != target.HostID {
			continue
		}
		if stored.CreatedMS > latest {
			latest = stored.CreatedMS
		}
		current, exists := byID[stored.ID]
		if !exists {
			current = Model{ID: stored.ID, LoadState: "unavailable", Provenance: domain.Provenance{Source: "collector_inventory", MethodRevision: "collector-inventory-v1", Verification: domain.VerificationDeclaredUnverified}}
		}
		alias := stored.Alias
		current.Alias = &alias
		if stored.Digest != nil {
			digest := *stored.Digest
			current.Digest = &digest
		}
		byID[stored.ID] = current
	}
	models := make([]Model, 0, len(byID))
	for _, model := range byID {
		models = append(models, model)
	}
	sort.Slice(models, func(i, j int) bool { return models[i].ID < models[j].ID })
	if len(models) == 0 || latest == 0 {
		return target.ModelsState, target.ModelsObservedMS, target.ModelsAgeMS, models
	}
	observed := latest
	age := ageMS(now, observed)
	if target.ModelsObservedMS != nil && *target.ModelsObservedMS > observed {
		observed = *target.ModelsObservedMS
		age = ageMS(now, observed)
	}
	if target.ModelsState == SourceNotObserved {
		state := SourceStale
		if age <= int64(45*time.Second/time.Millisecond) {
			state = SourceFresh
		}
		return state, &observed, &age, models
	}
	return target.ModelsState, target.ModelsObservedMS, target.ModelsAgeMS, models
}

func isModelComponent(frame protocol.CollectorFrame) bool {
	if frame.Provenance.MethodRevision == "ollama-0.34.0-bounded-ps-v1" || len(frame.ModelObservations) > 0 {
		return true
	}
	for _, missing := range frame.CapabilitiesMissing {
		if strings.HasPrefix(missing.ID, "runtime.model.") {
			return true
		}
	}
	return false
}

func latestCapabilities(frames []protocol.CollectorFrame) []domain.MissingCapability {
	seen := make(map[string]bool)
	seenComponents := make(map[string]bool)
	result := make([]domain.MissingCapability, 0)
	for _, frame := range frames {
		component := frameComponent(frame)
		if seenComponents[component] {
			continue
		}
		seenComponents[component] = true
		for _, missing := range frame.CapabilitiesMissing {
			if _, canonicalMetric := metricDefinitions[missing.ID]; canonicalMetric {
				continue
			}
			if !seen[missing.ID] {
				seen[missing.ID] = true
				result = append(result, missing)
			}
		}
		if len(result) >= 32 {
			return result
		}
	}
	return result
}

func frameComponent(frame protocol.CollectorFrame) string {
	if frame.ProcessSummary != nil {
		return "process"
	}
	if isNetworkComponent(frame) {
		return "network"
	}
	if isModelComponent(frame) {
		return "runtime_models"
	}
	for metric := range frame.Gauges {
		return metric
	}
	return frame.Provenance.MethodRevision
}

func unavailableReading(id, scopeID string, sourceID *string, reason domain.MissingReason, _ int64) MetricReading {
	definition := metricDefinitions[id]
	return MetricReading{
		Metric: id, Unit: definition.unit, ScopeID: scopeID, SourceID: sourceID, Value: nil, Quality: domain.QualityUnavailable, MissingReason: &reason,
		MethodRevision: definition.method, Provenance: domain.Provenance{Source: definition.source, MethodRevision: definition.method, Verification: domain.VerificationDeclaredUnverified},
	}
}

func hostSourceState(host store.QueryHost, status protocol.SourceStatus, exists bool, now int64, hostSourceIDs map[string]bool) SourceState {
	if host.RetiredMS != nil || host.CurrentSessionGeneration == 0 || host.LastBootID == nil {
		return SourceNotObserved
	}
	if !exists || ageMS(now, status.ObservedWallMS) > int64(60*time.Second/time.Millisecond) {
		return SourceDisconnected
	}
	state := SourceFresh
	if status.Heartbeat == "degraded" {
		state = SourcePartial
	}
	found := false
	for _, source := range status.Sources {
		if !hostSourceIDs[source.SourceID] {
			continue
		}
		found = true
		next := sourceStateFromStatus(source, now, 15*time.Second)
		state = worseState(state, next)
	}
	if !found {
		return worseState(state, SourceNotObserved)
	}
	return state
}

func activeSourceIDs(sources []store.QuerySource, hostID, kind string) map[string]bool {
	result := make(map[string]bool)
	for _, source := range sources {
		if source.HostID == hostID && source.Kind == kind && source.RetiredMS == nil {
			result[source.ID] = true
		}
	}
	return result
}

func sourceStateFor(source store.QuerySource, status protocol.SourceStatus, exists bool, now int64) SourceState {
	if source.RetiredMS != nil {
		return SourceNotObserved
	}
	if !exists || ageMS(now, status.ObservedWallMS) > int64(60*time.Second/time.Millisecond) {
		return SourceDisconnected
	}
	for _, value := range status.Sources {
		if value.SourceID == source.ID {
			freshness := 15 * time.Second
			if source.Kind == "runtime" {
				freshness = 45 * time.Second
			}
			return sourceStateFromStatus(value, now, freshness)
		}
	}
	return SourceNotObserved
}

func sourceStateFromStatus(source protocol.SourceState, now int64, freshness time.Duration) SourceState {
	switch source.State {
	case "incompatible":
		return SourceIncompatible
	case "unavailable":
		return SourceUnavailable
	case "stale":
		return SourceStale
	case "fresh":
		if source.LastSuccessMS == nil || ageMS(now, *source.LastSuccessMS) > freshness.Milliseconds() {
			return SourceStale
		}
		return SourceFresh
	default:
		return SourceNotObserved
	}
}

func hasNetworkCapability(values []domain.MissingCapability) bool {
	for _, value := range values {
		if strings.HasPrefix(value.ID, "host.network.") {
			return true
		}
	}
	return false
}

func worseState(left, right SourceState) SourceState {
	order := map[SourceState]int{SourceFresh: 0, SourceNotObserved: 1, SourceStale: 2, SourcePartial: 3, SourceUnavailable: 4, SourceIncompatible: 5, SourceDisconnected: 6}
	if order[right] > order[left] {
		return right
	}
	return left
}

func overviewState(hosts []Host, targets []Target) SourceState {
	state := SourceNotObserved
	active := false
	for _, host := range hosts {
		if host.State == "retired" || host.State == "revoked" {
			continue
		}
		if !active {
			state = SourceFresh
			active = true
		}
		state = worseState(state, host.SourceState)
	}
	for _, target := range targets {
		if target.Retired {
			continue
		}
		state = worseState(state, target.SourceState)
		state = worseState(state, target.ModelsState)
		if target.Reachable.Quality == domain.QualityUnavailable {
			state = worseState(state, SourceUnavailable)
		}
	}
	if !active {
		return SourceNotObserved
	}
	return state
}

func hostObservationPartial(host Host) bool {
	if host.NetworkObservedMS == nil || host.ProcessObservedMS == nil {
		return true
	}
	// A network component can retain useful bounded counters while also
	// reporting a failed field or interface-cap truncation. Both the zero-value
	// failure and the usable truncated population make the host partial; a later
	// successful network frame clears the component's missing capabilities.
	if hasNetworkCapability(host.CapabilitiesMissing) {
		return true
	}
	for _, metric := range host.Metrics {
		if metric.Quality == domain.QualityUnavailable {
			return true
		}
	}
	return false
}

func activeHostCount(hosts []store.QueryHost) int {
	count := 0
	for _, host := range hosts {
		if host.RetiredMS == nil {
			count++
		}
	}
	return count
}

func activeTargetCount(targets []store.QueryTarget) int {
	count := 0
	for _, target := range targets {
		if target.RetiredMS == nil {
			count++
		}
	}
	return count
}

func collectOverviewMissing(hosts []Host, targets []Target) []domain.MissingCapability {
	seen := make(map[string]bool)
	result := make([]domain.MissingCapability, 0)
	appendValues := func(values []domain.MissingCapability) {
		for _, value := range values {
			if len(result) == 32 || seen[value.ID] {
				continue
			}
			seen[value.ID] = true
			result = append(result, value)
		}
	}
	for _, host := range hosts {
		appendValues(host.CapabilitiesMissing)
	}
	for _, target := range targets {
		appendValues(target.CapabilitiesMissing)
	}
	return result
}

func optionalTimeAndAge(ok bool, observed, now int64) (*int64, *int64) {
	if !ok {
		return nil, nil
	}
	age := ageMS(now, observed)
	return &observed, &age
}

func ageMS(now, observed int64) int64 {
	if observed >= now {
		return 0
	}
	return now - observed
}

func cloneRaw(value json.RawMessage) json.RawMessage {
	if value == nil {
		return nil
	}
	return append(json.RawMessage(nil), value...)
}

func pointer[T any](value T) *T { return &value }
