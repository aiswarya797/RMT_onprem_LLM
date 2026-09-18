package ollama

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	adapter "rmt.local/monitor/internal/adapters/ollama"
	"rmt.local/monitor/internal/domain"
)

type fakeAPI struct {
	mu         sync.Mutex
	calls      []string
	root       adapter.RootObservation
	rootErr    error
	version    adapter.RuntimeVersion
	versionErr error
	loaded     adapter.ModelInventory
	loadedErr  error
	tags       adapter.ModelInventory
	tagsErr    error
	show       adapter.ModelInfo
	showErr    error
	showAlias  string
	showDigest *string
	rootWait   <-chan struct{}
}

func (f *fakeAPI) record(call string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
}
func (f *fakeAPI) Root(context.Context) (adapter.RootObservation, error) {
	f.record("root")
	if f.rootWait != nil {
		<-f.rootWait
	}
	return f.root, f.rootErr
}
func (f *fakeAPI) Version(context.Context) (adapter.RuntimeVersion, error) {
	f.record("version")
	return f.version, f.versionErr
}
func (f *fakeAPI) LoadedModels(context.Context) (adapter.ModelInventory, error) {
	f.record("ps")
	return f.loaded, f.loadedErr
}
func (f *fakeAPI) Tags(context.Context) (adapter.ModelInventory, error) {
	f.record("tags")
	return f.tags, f.tagsErr
}
func (f *fakeAPI) Show(_ context.Context, alias string, digest *string) (adapter.ModelInfo, error) {
	f.record("show")
	f.showAlias, f.showDigest = alias, digest
	return f.show, f.showErr
}

type fakeIDs struct {
	calls [][3]string
	id    string
	err   error
}

func (f *fakeIDs) ResolveModelID(_ context.Context, target, alias, digest string) (string, error) {
	f.calls = append(f.calls, [3]string{target, alias, digest})
	return f.id, f.err
}

type fakeClock struct {
	mu   sync.Mutex
	wall time.Time
	mono uint64
}

func (c *fakeClock) Now() (time.Time, uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	wall, mono := c.wall, c.mono
	c.wall = c.wall.Add(time.Millisecond)
	c.mono += uint64(time.Millisecond)
	return wall, mono
}

func TestReachabilityCadenceDoesNotPollInventory(t *testing.T) {
	api := &fakeAPI{root: adapter.RootObservation{Reachable: true}, version: adapter.RuntimeVersion{Version: "0.34.0", SourcePinID: "ollama-0.34.0-source", CompatibilityState: adapter.CompatibilityUnverified}}
	collector := NewWithClock(api, nil, Config{TargetID: "target"}, newFakeClock())
	snapshot := collector.CollectReachability(context.Background())
	if !snapshot.ReachabilityObserved || snapshot.InventoryObserved || snapshot.Runtime.Reachable.Value == nil || !*snapshot.Runtime.Reachable.Value {
		t.Fatalf("snapshot = %#v", snapshot)
	}
	if snapshot.Runtime.Version == nil || *snapshot.Runtime.Version != "0.34.0" || snapshot.Runtime.Build != nil {
		t.Fatalf("version/build = %v/%v", snapshot.Runtime.Version, snapshot.Runtime.Build)
	}
	if snapshot.RuntimeSourcePinID == nil || *snapshot.RuntimeSourcePinID != "ollama-0.34.0-source" || snapshot.RuntimeCompatibility == nil || *snapshot.RuntimeCompatibility != adapter.CompatibilityUnverified {
		t.Fatalf("runtime provenance = %v/%v", snapshot.RuntimeSourcePinID, snapshot.RuntimeCompatibility)
	}
	if got := api.callList(); !equalStrings(got, []string{"root", "version"}) {
		t.Fatalf("calls = %v", got)
	}
	if !hasMissing(snapshot.Runtime.CapabilitiesMissing, "runtime.version.certification", domain.MissingRuntimeUnverified) {
		t.Fatal("source inspection was incorrectly treated as runtime certification")
	}
}

func TestInventoryCadenceDoesNotPollReachabilityAndKeepsAliasDigestSeparate(t *testing.T) {
	digest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	size, vram := uint64(10), uint64(0)
	api := &fakeAPI{
		loaded: adapter.ModelInventory{Models: []adapter.Model{{Alias: "alias-a", Digest: &digest, Loaded: true, Local: true, ReportedSizeBytes: &size, SizeVRAMBytes: &vram}}},
		tags:   adapter.ModelInventory{Models: []adapter.Model{{Alias: "alias-b", Digest: &digest, Local: true}}},
		show:   adapter.ModelInfo{Alias: "alias-b", Digest: &digest},
	}
	ids := &fakeIDs{id: "11111111-1111-4111-8111-111111111111"}
	collector := NewWithClock(api, ids, Config{TargetID: "22222222-2222-4222-8222-222222222222", SelectedModelAlias: "alias-b"}, newFakeClock())
	snapshot := collector.CollectInventory(context.Background())
	if snapshot.ReachabilityObserved || !snapshot.InventoryObserved || len(snapshot.Runtime.Models) != 1 || len(snapshot.AvailableModels) != 1 {
		t.Fatalf("snapshot = %#v", snapshot)
	}
	if got := api.callList(); !equalStrings(got, []string{"ps", "tags", "show"}) {
		t.Fatalf("calls = %v", got)
	}
	if api.showAlias != "alias-b" || api.showDigest == nil || *api.showDigest != digest {
		t.Fatalf("show selector = %q/%v", api.showAlias, api.showDigest)
	}
	if len(ids.calls) != 1 || ids.calls[0][1] != "alias-a" || ids.calls[0][2] != digest {
		t.Fatalf("identity calls = %v", ids.calls)
	}
	model := snapshot.Runtime.Models[0]
	if model.ReportedSizeBytes == nil || *model.ReportedSizeBytes != "10" || model.ReportedSizeVRAMBytes == nil || *model.ReportedSizeVRAMBytes != "0" {
		t.Fatalf("model sizes = %#v", model)
	}
}

func TestConfigObservationTracksSuccessfulEpochsAndOmitsPartialSelectedSnapshot(t *testing.T) {
	targetID := "22222222-2222-4222-8222-222222222222"
	digest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	format, family, quantization, contextLength := "gguf", "qwen3", "Q4_K_M", uint64(4096)
	api := &fakeAPI{
		root:    adapter.RootObservation{Reachable: true},
		version: adapter.RuntimeVersion{Version: "0.34.0", SourcePinID: "ollama-0.34.0-source", CompatibilityState: adapter.CompatibilityUnverified},
		loaded:  adapter.ModelInventory{Models: []adapter.Model{{Alias: "selected", Digest: &digest, Loaded: true, Local: true}}},
		tags:    adapter.ModelInventory{Models: []adapter.Model{{Alias: "selected", Digest: &digest, Local: true}}},
		show:    adapter.ModelInfo{Alias: "selected", Digest: &digest, Details: adapter.ModelDetails{Format: &format, Family: &family, QuantizationLevel: &quantization, ContextLength: &contextLength}},
	}
	collector := NewWithClock(api, &fakeIDs{id: "11111111-1111-4111-8111-111111111111"}, Config{TargetID: targetID, SelectedModelAlias: "selected"}, newFakeClock())
	first := collector.Collect(context.Background(), Due{Reachability: true, Inventory: true})
	if first.Runtime.Config == nil || first.Runtime.Config.PreviousConfigHash != nil || first.Runtime.Config.Fields.SelectedModel == nil || first.Runtime.Config.Fields.SelectedModel.Alias != "selected" {
		t.Fatalf("first config=%#v", first.Runtime.Config)
	}
	if got := domain.RuntimeConfigHash(first.Runtime.Config.Fields, first.Runtime.Config.FieldProvenance); got != first.Runtime.Config.ConfigHash {
		t.Fatalf("first config hash=%q want=%q", first.Runtime.Config.ConfigHash, got)
	}
	firstHash, firstMS := first.Runtime.Config.ConfigHash, first.Runtime.ComponentTimings.Config.ObservedWallMS

	api.version.Version = "0.35.0"
	second := collector.Collect(context.Background(), Due{Reachability: true, Inventory: true})
	if second.Runtime.Config == nil || second.Runtime.Config.ConfigHash == firstHash || second.Runtime.Config.PreviousConfigHash == nil || *second.Runtime.Config.PreviousConfigHash != firstHash || second.Runtime.Config.PreviousObservedMS == nil || *second.Runtime.Config.PreviousObservedMS != firstMS {
		t.Fatalf("second config=%#v", second.Runtime.Config)
	}
	secondHash, secondMS := second.Runtime.Config.ConfigHash, second.Runtime.ComponentTimings.Config.ObservedWallMS

	api.showErr = &adapter.AdapterError{Kind: adapter.ErrorTimeout, Err: errors.New("show timeout")}
	partial := collector.Collect(context.Background(), Due{Reachability: true, Inventory: true})
	if partial.Runtime.Config != nil || !hasMissingID(partial.Runtime.CapabilitiesMissing, "runtime.model.selected_metadata") {
		t.Fatalf("partial config=%#v missing=%#v", partial.Runtime.Config, partial.Runtime.CapabilitiesMissing)
	}
	api.showErr = nil
	api.version.Version = "0.34.0"
	recurrence := collector.Collect(context.Background(), Due{Reachability: true, Inventory: true})
	if recurrence.Runtime.Config == nil || recurrence.Runtime.Config.ConfigHash != firstHash || recurrence.Runtime.Config.PreviousConfigHash == nil || *recurrence.Runtime.Config.PreviousConfigHash != secondHash || recurrence.Runtime.Config.PreviousObservedMS == nil || *recurrence.Runtime.Config.PreviousObservedMS != secondMS {
		t.Fatalf("recurrence config=%#v", recurrence.Runtime.Config)
	}
}

func TestVersionOnlyConfigDoesNotDependOnInventorySuccess(t *testing.T) {
	targetID := "22222222-2222-4222-8222-222222222222"
	api := &fakeAPI{
		root:      adapter.RootObservation{Reachable: true},
		version:   adapter.RuntimeVersion{Version: "0.34.0", CompatibilityState: adapter.CompatibilityUnverified},
		loadedErr: &adapter.AdapterError{Kind: adapter.ErrorMalformed, Err: errors.New("bad ps")},
		tagsErr:   &adapter.AdapterError{Kind: adapter.ErrorTimeout, Err: errors.New("tags timeout")},
	}
	snapshot := NewWithClock(api, &fakeIDs{id: "unused"}, Config{TargetID: targetID}, newFakeClock()).Collect(context.Background(), Due{Reachability: true, Inventory: true})
	if snapshot.Runtime.Config == nil || snapshot.Runtime.Config.Fields.ServerVersion != "0.34.0" || snapshot.Runtime.Config.Fields.SelectedModel != nil {
		t.Fatalf("version-only config=%#v", snapshot.Runtime.Config)
	}
}

func TestReachabilityFalseAndProtocolUnavailableRemainDistinct(t *testing.T) {
	unreachable := &adapter.AdapterError{Kind: adapter.ErrorUnreachable, Err: errors.New("connection refused")}
	api := &fakeAPI{rootErr: unreachable, versionErr: unreachable}
	collector := NewWithClock(api, nil, Config{}, newFakeClock())
	failed := collector.CollectReachability(context.Background())
	if failed.Runtime.Reachable.Value == nil || *failed.Runtime.Reachable.Value || failed.Runtime.Reachable.Quality != domain.QualityRuntimeReported {
		t.Fatalf("unreachable = %#v", failed.Runtime.Reachable)
	}

	malformed := &adapter.AdapterError{Kind: adapter.ErrorMalformed, Err: errors.New("wrong service")}
	api = &fakeAPI{rootErr: unreachable, versionErr: malformed}
	collector = NewWithClock(api, nil, Config{}, newFakeClock())
	protocol := collector.CollectReachability(context.Background())
	if protocol.Runtime.Reachable.Value != nil || protocol.Runtime.Reachable.Quality != domain.QualityUnavailable || protocol.Runtime.Reachable.MissingReason == nil || *protocol.Runtime.Reachable.MissingReason != domain.MissingParseRejected {
		t.Fatalf("protocol = %#v", protocol.Runtime.Reachable)
	}
}

func TestEmptyLoadedInventoryIsAValidUnloadedObservation(t *testing.T) {
	api := &fakeAPI{loaded: adapter.ModelInventory{}, tags: adapter.ModelInventory{}}
	collector := NewWithClock(api, &fakeIDs{id: "unused"}, Config{}, newFakeClock())
	snapshot := collector.CollectInventory(context.Background())
	if len(snapshot.Runtime.Models) != 0 || hasMissingID(snapshot.Runtime.CapabilitiesMissing, "runtime.model.loaded") {
		t.Fatalf("empty inventory misclassified: %#v", snapshot)
	}
}

func TestInventoryFailureKeepsIndependentTagsObservation(t *testing.T) {
	digest := "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	api := &fakeAPI{
		loadedErr: &adapter.AdapterError{Kind: adapter.ErrorMalformed, Err: errors.New("bad ps")},
		tags:      adapter.ModelInventory{Models: []adapter.Model{{Alias: "available", Digest: &digest, Local: true}}},
	}
	collector := NewWithClock(api, &fakeIDs{id: "unused"}, Config{}, newFakeClock())
	snapshot := collector.CollectInventory(context.Background())
	if len(snapshot.AvailableModels) != 1 || !hasMissing(snapshot.Runtime.CapabilitiesMissing, "runtime.model.loaded", domain.MissingParseRejected) {
		t.Fatalf("partial inventory = %#v", snapshot)
	}
}

func TestMissingDigestAndIdentityFailureStayUnavailable(t *testing.T) {
	digest := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	api := &fakeAPI{loaded: adapter.ModelInventory{Models: []adapter.Model{{Alias: "no-digest", Loaded: true}, {Alias: "has-digest", Digest: &digest, Loaded: true}}}}
	collector := NewWithClock(api, &fakeIDs{err: errors.New("store unavailable")}, Config{}, newFakeClock())
	snapshot := collector.CollectInventory(context.Background())
	if len(snapshot.Runtime.Models) != 0 || !hasMissingID(snapshot.Runtime.CapabilitiesMissing, "runtime.model.digest") || !hasMissingID(snapshot.Runtime.CapabilitiesMissing, "runtime.model.identity") {
		t.Fatalf("snapshot = %#v", snapshot)
	}
}

func TestSelectedShowRequiresObservedLocalModel(t *testing.T) {
	digest := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	for name, models := range map[string][]adapter.Model{
		"unobserved": nil,
		"remote":     {{Alias: "selected", Digest: &digest, Local: false}},
	} {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{tags: adapter.ModelInventory{Models: models}}
			collector := NewWithClock(api, &fakeIDs{id: "unused"}, Config{SelectedModelAlias: "selected"}, newFakeClock())
			snapshot := collector.CollectInventory(context.Background())
			if containsString(api.callList(), "show") || !hasMissing(snapshot.Runtime.CapabilitiesMissing, "runtime.model.selected_metadata", domain.MissingIdentityUnverified) {
				t.Fatalf("calls/snapshot = %v/%#v", api.callList(), snapshot)
			}
		})
	}
}

func TestCollectorSkipsOverlappingTargetOperation(t *testing.T) {
	release := make(chan struct{})
	api := &fakeAPI{rootWait: release, root: adapter.RootObservation{Reachable: true}, version: adapter.RuntimeVersion{Version: "0.34.0", CompatibilityState: adapter.CompatibilityUnverified}}
	collector := NewWithClock(api, nil, Config{}, newFakeClock())
	done := make(chan Snapshot, 1)
	go func() { done <- collector.CollectReachability(context.Background()) }()
	for {
		api.mu.Lock()
		entered := len(api.calls) > 0
		api.mu.Unlock()
		if entered {
			break
		}
		time.Sleep(time.Millisecond)
	}
	started := time.Now()
	skipped := collector.CollectInventory(context.Background())
	if time.Since(started) > 100*time.Millisecond || !hasMissing(skipped.Runtime.CapabilitiesMissing, "runtime.model.loaded", domain.MissingSourceTimeout) {
		t.Fatalf("skipped = %#v, elapsed = %v", skipped, time.Since(started))
	}
	close(release)
	<-done
}

func (f *fakeAPI) callList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}
func newFakeClock() *fakeClock { return &fakeClock{wall: time.Unix(1_789_473_600, 0)} }
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func hasMissing(values []domain.MissingCapability, id string, reason domain.MissingReason) bool {
	for _, value := range values {
		if value.ID == id && value.Reason == reason {
			return true
		}
	}
	return false
}
func hasMissingID(values []domain.MissingCapability, id string) bool {
	for _, value := range values {
		if value.ID == id {
			return true
		}
	}
	return false
}
func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
