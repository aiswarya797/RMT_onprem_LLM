package ollama

import (
	"context"
	"fmt"
	"sync"
	"time"

	adapter "rmt.local/monitor/internal/adapters/ollama"
	"rmt.local/monitor/internal/domain"
)

const MethodRevision = "ollama-0.34.0-bounded-read-v1"

type ReadOnlyAPI interface {
	Root(context.Context) (adapter.RootObservation, error)
	Version(context.Context) (adapter.RuntimeVersion, error)
	LoadedModels(context.Context) (adapter.ModelInventory, error)
	Tags(context.Context) (adapter.ModelInventory, error)
	Show(context.Context, string, *string) (adapter.ModelInfo, error)
}

// ModelIdentityStore owns random stable IDs. The collector deliberately does
// not derive an ID from an alias or digest.
type ModelIdentityStore interface {
	ResolveModelID(ctx context.Context, targetID, alias, digest string) (string, error)
}

type Clock interface {
	Now() (wall time.Time, monotonicNS uint64)
}

type systemClock struct{ origin time.Time }

func newSystemClock() systemClock { return systemClock{origin: time.Now()} }
func (c systemClock) Now() (time.Time, uint64) {
	return time.Now(), uint64(time.Since(c.origin))
}

type Config struct {
	TargetID           string
	SelectedModelAlias string
}

type Due struct {
	Reachability bool
	Inventory    bool
}

type Snapshot struct {
	ReachabilityObserved bool
	InventoryObserved    bool
	Runtime              domain.RuntimeObservation
	RuntimeSourcePinID   *string
	RuntimeCompatibility *adapter.CompatibilityState
	AvailableModels      []adapter.Model
	LoadedModels         []adapter.Model
	SelectedModel        *adapter.ModelInfo
}

type Collector struct {
	api         ReadOnlyAPI
	models      ModelIdentityStore
	clock       Clock
	config      Config
	operationMu sync.Mutex
	lastConfig  *configObservationState
}

type configObservationState struct {
	hash       string
	observedMS int64
}

func New(api ReadOnlyAPI, models ModelIdentityStore, config Config) *Collector {
	return &Collector{api: api, models: models, clock: newSystemClock(), config: config}
}

func NewWithClock(api ReadOnlyAPI, models ModelIdentityStore, config Config, clock Clock) *Collector {
	return &Collector{api: api, models: models, clock: clock, config: config}
}

func (c *Collector) Collect(ctx context.Context, due Due) Snapshot {
	if !c.operationMu.TryLock() {
		return c.skipped(due)
	}
	defer c.operationMu.Unlock()

	snapshot := Snapshot{}
	if due.Reachability {
		snapshot.ReachabilityObserved = true
		c.collectReachability(ctx, &snapshot)
	}
	if due.Inventory {
		snapshot.InventoryObserved = true
		c.collectInventory(ctx, &snapshot)
		c.captureConfig(&snapshot)
	}
	return snapshot
}

func (c *Collector) CollectReachability(ctx context.Context) Snapshot {
	return c.Collect(ctx, Due{Reachability: true})
}

func (c *Collector) CollectInventory(ctx context.Context) Snapshot {
	return c.Collect(ctx, Due{Inventory: true})
}

func (c *Collector) collectReachability(ctx context.Context, snapshot *Snapshot) {
	observation := &snapshot.Runtime
	reachContext, cancelReach := context.WithTimeout(ctx, adapter.RequestTimeout)
	reachStartWall, reachStart := c.clock.Now()
	_, rootErr := c.api.Root(reachContext)
	versionStartWall, versionStart := c.clock.Now()
	version, versionErr := c.api.Version(reachContext)
	_, versionEnd := c.clock.Now()
	cancelReach()
	_, reachEnd := c.clock.Now()
	observation.ComponentTimings.Reachability = domain.NewComponentTiming(midpointWall(reachStartWall, reachStart, reachEnd), reachStart, reachEnd)
	versionTiming := domain.NewComponentTiming(midpointWall(versionStartWall, versionStart, versionEnd), versionStart, versionEnd)
	observation.ComponentTimings.Version = &versionTiming

	provenance := c.provenance(reachStartWall)
	reachable, reachMissing := reachability(rootErr, versionErr, provenance)
	observation.Reachable = reachable
	if reachMissing != nil {
		observation.CapabilitiesMissing = append(observation.CapabilitiesMissing, *reachMissing)
	}
	if versionErr == nil {
		observation.Version = &version.Version
		sourcePinID := version.SourcePinID
		compatibility := version.CompatibilityState
		snapshot.RuntimeSourcePinID = &sourcePinID
		snapshot.RuntimeCompatibility = &compatibility
		if version.CompatibilityState == adapter.CompatibilityUnverified {
			observation.CapabilitiesMissing = append(observation.CapabilitiesMissing, missing("runtime.version.certification", domain.MissingRuntimeUnverified, "exact_runtime_t24_pending"))
		}
	} else {
		observation.CapabilitiesMissing = append(observation.CapabilitiesMissing, missing("runtime.version", missingReason(versionErr), detail(adapter.ErrorKindOf(versionErr))))
	}
	observation.CapabilitiesMissing = append(observation.CapabilitiesMissing, missing("runtime.build", domain.MissingFieldOmitted, "ollama_version_endpoint_omits_build"))
}

func (c *Collector) collectInventory(ctx context.Context, snapshot *Snapshot) {
	provenanceWall, _ := c.clock.Now()
	provenance := c.provenance(provenanceWall)
	inventoryContext, cancelInventory := context.WithTimeout(ctx, adapter.RequestTimeout)
	defer cancelInventory()
	loadedStartWall, loadedStart := c.clock.Now()
	loaded, loadedErr := c.api.LoadedModels(inventoryContext)
	_, loadedEnd := c.clock.Now()
	loadedTiming := domain.NewComponentTiming(midpointWall(loadedStartWall, loadedStart, loadedEnd), loadedStart, loadedEnd)
	snapshot.Runtime.ComponentTimings.LoadedModels = &loadedTiming
	if loadedErr != nil {
		snapshot.Runtime.CapabilitiesMissing = append(snapshot.Runtime.CapabilitiesMissing, missing("runtime.model.loaded", missingReason(loadedErr), detail(adapter.ErrorKindOf(loadedErr))))
	} else {
		snapshot.LoadedModels = append([]adapter.Model(nil), loaded.Models...)
		snapshot.Runtime.Models = c.modelObservations(inventoryContext, loaded.Models, provenance, &snapshot.Runtime.CapabilitiesMissing)
	}

	tagsStartWall, tagsStart := c.clock.Now()
	tags, tagsErr := c.api.Tags(inventoryContext)
	_, tagsEnd := c.clock.Now()
	tagsTiming := domain.NewComponentTiming(midpointWall(tagsStartWall, tagsStart, tagsEnd), tagsStart, tagsEnd)
	snapshot.Runtime.ComponentTimings.Tags = &tagsTiming
	if tagsErr != nil {
		snapshot.Runtime.CapabilitiesMissing = append(snapshot.Runtime.CapabilitiesMissing, missing("runtime.model.tags", missingReason(tagsErr), detail(adapter.ErrorKindOf(tagsErr))))
	} else {
		snapshot.AvailableModels = append([]adapter.Model(nil), tags.Models...)
	}

	if c.config.SelectedModelAlias != "" {
		selectedDigest, selectedLocal, selectedObserved := findSelected(c.config.SelectedModelAlias, loaded.Models, tags.Models)
		if !selectedObserved || !selectedLocal {
			snapshot.Runtime.CapabilitiesMissing = append(snapshot.Runtime.CapabilitiesMissing, missing("runtime.model.selected_metadata", domain.MissingIdentityUnverified, "selected_model_not_observed_local"))
			return
		}
		showStartWall, showStart := c.clock.Now()
		show, showErr := c.api.Show(inventoryContext, c.config.SelectedModelAlias, selectedDigest)
		_, showEnd := c.clock.Now()
		showTiming := domain.NewComponentTiming(midpointWall(showStartWall, showStart, showEnd), showStart, showEnd)
		snapshot.Runtime.ComponentTimings.SelectedShow = &showTiming
		if showErr != nil {
			snapshot.Runtime.CapabilitiesMissing = append(snapshot.Runtime.CapabilitiesMissing, missing("runtime.model.selected_metadata", missingReason(showErr), detail(adapter.ErrorKindOf(showErr))))
		} else {
			snapshot.SelectedModel = &show
		}
	}
}

func (c *Collector) captureConfig(snapshot *Snapshot) {
	if snapshot.Runtime.Version == nil || snapshot.Runtime.ComponentTimings.Version == nil || c.config.TargetID == "" {
		return
	}
	// An explicitly selected model makes its bounded /api/show fields part of
	// the whole snapshot. A failed or incomplete selected-model read therefore
	// omits the config observation instead of hashing missing fields as a change.
	if c.config.SelectedModelAlias != "" && snapshot.SelectedModel == nil {
		return
	}
	versionProvenance := c.provenance(time.UnixMilli(snapshot.Runtime.ComponentTimings.Version.ObservedWallMS))
	fields := domain.RuntimeConfigFields{ServerVersion: *snapshot.Runtime.Version, ServerBuild: snapshot.Runtime.Build}
	fieldProvenance := domain.RuntimeConfigFieldProvenance{ServerVersion: versionProvenance}
	timing := *snapshot.Runtime.ComponentTimings.Version
	if fields.ServerBuild != nil {
		value := versionProvenance
		fieldProvenance.ServerBuild = &value
	}
	if snapshot.SelectedModel != nil && snapshot.Runtime.ComponentTimings.SelectedShow != nil {
		show := snapshot.SelectedModel
		fields.SelectedModel = &domain.RuntimeSelectedModelConfig{
			Alias: show.Alias, Digest: show.Digest, Format: show.Details.Format, Family: show.Details.Family,
			Quantization: show.Details.QuantizationLevel, ContextLength: show.Details.ContextLength,
		}
		showProvenance := c.provenance(time.UnixMilli(snapshot.Runtime.ComponentTimings.SelectedShow.ObservedWallMS))
		selectedProvenance := &domain.RuntimeSelectedModelFieldProvenance{Alias: showProvenance}
		selectedProvenance.Digest = provenanceWhenPresent(show.Digest, showProvenance)
		selectedProvenance.Format = provenanceWhenPresent(show.Details.Format, showProvenance)
		selectedProvenance.Family = provenanceWhenPresent(show.Details.Family, showProvenance)
		selectedProvenance.Quantization = provenanceWhenPresent(show.Details.QuantizationLevel, showProvenance)
		if show.Details.ContextLength != nil {
			value := showProvenance
			selectedProvenance.ContextLength = &value
		}
		fieldProvenance.SelectedModel = selectedProvenance
		timing = *snapshot.Runtime.ComponentTimings.SelectedShow
	}
	hash := domain.RuntimeConfigHash(fields, fieldProvenance)
	observation := &domain.RuntimeConfigObservation{TargetID: c.config.TargetID, ConfigHash: hash, Fields: fields, FieldProvenance: fieldProvenance}
	if c.lastConfig != nil && c.lastConfig.observedMS < timing.ObservedWallMS {
		previousHash, previousMS := c.lastConfig.hash, c.lastConfig.observedMS
		observation.PreviousConfigHash, observation.PreviousObservedMS = &previousHash, &previousMS
	}
	snapshot.Runtime.Config = observation
	snapshot.Runtime.ComponentTimings.Config = &timing
	c.lastConfig = &configObservationState{hash: hash, observedMS: timing.ObservedWallMS}
}

func provenanceWhenPresent[T any](value *T, provenance domain.Provenance) *domain.Provenance {
	if value == nil {
		return nil
	}
	copy := provenance
	return &copy
}

func (c *Collector) skipped(due Due) Snapshot {
	wall, mono := c.clock.Now()
	provenance := c.provenance(wall)
	snapshot := Snapshot{}
	if due.Reachability {
		snapshot.ReachabilityObserved = true
		snapshot.Runtime.ComponentTimings.Reachability = domain.NewComponentTiming(wall, mono, mono)
		snapshot.Runtime.Reachable = domain.Unavailable[bool](domain.MissingSourceTimeout, provenance)
		snapshot.Runtime.CapabilitiesMissing = append(snapshot.Runtime.CapabilitiesMissing, missing("runtime.reachable", domain.MissingSourceTimeout, "previous_target_operation_active"))
	}
	if due.Inventory {
		snapshot.InventoryObserved = true
		timing := domain.NewComponentTiming(wall, mono, mono)
		snapshot.Runtime.ComponentTimings.LoadedModels = &timing
		snapshot.Runtime.ComponentTimings.Tags = &timing
		snapshot.Runtime.CapabilitiesMissing = append(snapshot.Runtime.CapabilitiesMissing,
			missing("runtime.model.loaded", domain.MissingSourceTimeout, "previous_target_operation_active"),
			missing("runtime.model.tags", domain.MissingSourceTimeout, "previous_target_operation_active"))
	}
	return snapshot
}

func (c *Collector) modelObservations(ctx context.Context, models []adapter.Model, provenance domain.Provenance, missingList *[]domain.MissingCapability) []domain.ModelObservation {
	result := make([]domain.ModelObservation, 0, len(models))
	for _, model := range models {
		if model.Digest == nil {
			*missingList = append(*missingList, missing("runtime.model.digest", domain.MissingFieldOmitted, "loaded_model_digest_omitted"))
			continue
		}
		if c.models == nil {
			*missingList = append(*missingList, missing("runtime.model.identity", domain.MissingIdentityUnverified, "model_identity_store_unavailable"))
			continue
		}
		modelID, err := c.models.ResolveModelID(ctx, c.config.TargetID, model.Alias, *model.Digest)
		if err != nil || modelID == "" {
			*missingList = append(*missingList, missing("runtime.model.identity", domain.MissingIdentityUnverified, "model_identity_resolution_failed"))
			continue
		}
		observation := domain.ModelObservation{ModelID: modelID, Digest: *model.Digest, Loaded: true, Provenance: provenance}
		if model.ReportedSizeBytes != nil {
			value := domain.DecimalUint64(*model.ReportedSizeBytes)
			observation.ReportedSizeBytes = &value
		} else {
			observation.Missing = append(observation.Missing, missing("runtime.model.reported_size_bytes", domain.MissingFieldOmitted, "size_omitted"))
		}
		if model.SizeVRAMBytes != nil {
			value := domain.DecimalUint64(*model.SizeVRAMBytes)
			observation.ReportedSizeVRAMBytes = &value
		} else {
			observation.Missing = append(observation.Missing, missing("runtime.model.reported_size_vram_bytes", domain.MissingFieldOmitted, "size_vram_omitted"))
		}
		result = append(result, observation)
	}
	return result
}

func (c *Collector) provenance(observed time.Time) domain.Provenance {
	ms := observed.UnixMilli()
	return domain.Provenance{Source: domain.ProvenanceRuntimeAPI, MethodRevision: MethodRevision, Verification: domain.VerificationDirectCapture, ObservedAtMS: &ms}
}

func reachability(rootErr, versionErr error, provenance domain.Provenance) (domain.MetricObservation[bool], *domain.MissingCapability) {
	if rootErr == nil || versionErr == nil {
		return domain.RuntimeReported(true, provenance), nil
	}
	if adapter.ErrorKindOf(rootErr) == adapter.ErrorUnreachable && adapter.ErrorKindOf(versionErr) == adapter.ErrorUnreachable {
		return domain.RuntimeReported(false, provenance), nil
	}
	reason := missingReason(rootErr)
	if adapter.ErrorKindOf(versionErr) != adapter.ErrorUnreachable {
		reason = missingReason(versionErr)
	}
	value := domain.Unavailable[bool](reason, provenance)
	capability := missing("runtime.reachable", reason, fmt.Sprintf("root_%s_version_%s", adapter.ErrorKindOf(rootErr), adapter.ErrorKindOf(versionErr)))
	return value, &capability
}

func missingReason(err error) domain.MissingReason {
	switch adapter.ErrorKindOf(err) {
	case adapter.ErrorUnreachable:
		return domain.MissingSourceUnreachable
	case adapter.ErrorLimitExceeded:
		return domain.MissingLimitExceeded
	case adapter.ErrorBusy, adapter.ErrorTimeout:
		return domain.MissingSourceTimeout
	default:
		return domain.MissingParseRejected
	}
}

func findSelected(alias string, groups ...[]adapter.Model) (*string, bool, bool) {
	for _, models := range groups {
		for _, model := range models {
			if model.Alias == alias {
				if model.Digest == nil {
					return nil, model.Local, true
				}
				value := *model.Digest
				return &value, model.Local, true
			}
		}
	}
	return nil, false, false
}

func midpointWall(startWall time.Time, startNS, endNS uint64) time.Time {
	if endNS < startNS {
		return startWall
	}
	return startWall.Add(time.Duration((endNS - startNS) / 2))
}

func missing(id string, reason domain.MissingReason, detailCode string) domain.MissingCapability {
	return domain.MissingCapability{ID: id, Reason: reason, DetailCode: &detailCode}
}

func detail(kind adapter.ErrorKind) string { return string(kind) }
