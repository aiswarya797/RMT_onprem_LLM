package darwin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"rmt.local/monitor/internal/collect/identity"
	"rmt.local/monitor/internal/domain"
)

const (
	testHostID   = "11111111-1111-4111-8111-111111111111"
	testBootID   = "22222222-2222-4222-8222-222222222222"
	testTargetID = "33333333-3333-4333-8333-333333333333"
)

type fakeNativeReader struct {
	monotonic atomic.Uint64
	logical   int

	mu                 sync.Mutex
	cpuReads           []CPUTicks
	cpuIndex           int
	pressureFlag       uint32
	pressureBlock      <-chan struct{}
	pressureCalls      int
	osBuildCalls       int
	osBuild            string
	compressed         uint64
	swap               uint64
	disk               uint64
	interfaces         []InterfaceCounters
	interfacesTruncate bool
	pids               []int
	pidsTruncated      bool
	processes          map[int]ProcessRead
	processErrors      map[int]error
	listeners          map[int]bool
	listenerErrors     map[int]error
	processReadCalls   int
}

func newFakeNativeReader() *fakeNativeReader {
	reader := &fakeNativeReader{
		logical: 4, pressureFlag: 1, osBuild: "24F74", compressed: 10, swap: 20, disk: 30,
		cpuReads:  []CPUTicks{{User: 10, System: 5, Idle: 85}, {User: 20, System: 10, Idle: 170}},
		processes: make(map[int]ProcessRead), processErrors: make(map[int]error), listeners: make(map[int]bool), listenerErrors: make(map[int]error),
	}
	reader.monotonic.Store(uint64(time.Second))
	return reader
}

func (reader *fakeNativeReader) MonotonicNS() uint64 {
	return reader.monotonic.Add(uint64(time.Millisecond))
}

func (reader *fakeNativeReader) OSBuild(context.Context) (string, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	reader.osBuildCalls++
	return reader.osBuild, nil
}

func (reader *fakeNativeReader) HostCPUTicks(context.Context) (CPUTicks, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if len(reader.cpuReads) == 0 {
		return CPUTicks{}, errors.New("no cpu fixture")
	}
	index := min(reader.cpuIndex, len(reader.cpuReads)-1)
	reader.cpuIndex++
	return reader.cpuReads[index], nil
}

func (reader *fakeNativeReader) MemoryPressureFlag(context.Context) (uint32, error) {
	reader.mu.Lock()
	reader.pressureCalls++
	block, flag := reader.pressureBlock, reader.pressureFlag
	reader.mu.Unlock()
	if block != nil {
		<-block
	}
	return flag, nil
}

func (reader *fakeNativeReader) CompressedBytes(context.Context) (uint64, error) {
	return reader.compressed, nil
}

func (reader *fakeNativeReader) SwapUsedBytes(context.Context) (uint64, error) {
	return reader.swap, nil
}
func (reader *fakeNativeReader) DiskAvailableBytes(context.Context, string) (uint64, error) {
	return reader.disk, nil
}

func (reader *fakeNativeReader) Interfaces(context.Context) ([]InterfaceCounters, bool, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return append([]InterfaceCounters(nil), reader.interfaces...), reader.interfacesTruncate, nil
}

func (reader *fakeNativeReader) SameUserPIDs(context.Context, int) ([]int, bool, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return append([]int(nil), reader.pids...), reader.pidsTruncated, nil
}

func (reader *fakeNativeReader) Process(_ context.Context, pid int) (ProcessRead, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	reader.processReadCalls++
	if err := reader.processErrors[pid]; err != nil {
		return ProcessRead{}, err
	}
	value, ok := reader.processes[pid]
	if !ok {
		return ProcessRead{}, ErrProcessExited
	}
	return value, nil
}

func (reader *fakeNativeReader) PIDListensOnEndpoint(_ context.Context, pid int, start uint64, host string, port uint16) (bool, error) {
	if host != "127.0.0.1" || port != 11434 {
		return false, ErrUnsupported
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if value, ok := reader.processes[pid]; !ok || value.Identity.StartAbsolute != start {
		return false, ErrIdentityChanged
	}
	if err := reader.listenerErrors[pid]; err != nil {
		return false, err
	}
	return reader.listeners[pid], nil
}

func (reader *fakeNativeReader) LogicalCPUCount() int { return reader.logical }

func TestHostCollectionPreservesSemanticsAndCounterEpochs(t *testing.T) {
	reader := newFakeNativeReader()
	reader.compressed = math.MaxUint64
	reader.interfaces = []InterfaceCounters{{Index: 2, Name: "private-interface-name", Received: 9007199254740993, Sent: math.MaxUint64}}
	uuidIndex := 0
	collector, err := NewHostCollector(HostOptions{
		HostID: testHostID, BootID: testBootID, DataPath: t.TempDir(), Reader: reader,
		PressureQualified: func(build string) bool { return build == "24F74" },
		NewUUID: func() (string, error) {
			uuidIndex++
			return fmt.Sprintf("44444444-4444-4444-8444-%012d", uuidIndex), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	first := collector.Collect(context.Background())
	if first.Gauges.CPUBusyRatio.Quality != domain.QualityUnavailable || dereference(first.Gauges.CPUBusyRatio.MissingReason) != domain.MissingCollectionGap {
		t.Fatalf("first CPU sample should be a gap: %+v", first.Gauges.CPUBusyRatio)
	}
	if first.Gauges.PressureLevel.Value == nil || *first.Gauges.PressureLevel.Value != domain.PressureNormal {
		t.Fatalf("qualified pressure mapping failed: %+v", first.Gauges.PressureLevel)
	}
	if first.Gauges.PressureLevel.Provenance.SourceArtifactSHA256 == nil || *first.Gauges.PressureLevel.Provenance.SourceArtifactSHA256 != pressureSourceSHA256 {
		t.Fatal("pressure observation lost its verified XNU source artifact")
	}
	if got := string(dereference(first.Gauges.CompressedBytes.Value)); got != "18446744073709551615" {
		t.Fatalf("physical compressed bytes lost uint64 precision: %s", got)
	}
	if len(first.NetworkObservations) != 1 {
		t.Fatalf("network observations=%d", len(first.NetworkObservations))
	}
	network := first.NetworkObservations[0]
	if string(dereference(network.ReceivedBytesTotal)) != "9007199254740993" || string(dereference(network.SentBytesTotal)) != "18446744073709551615" {
		t.Fatalf("network counters lost precision: %+v", network)
	}
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "private-interface-name") {
		t.Fatal("raw interface name escaped the collector")
	}
	firstEpoch := network.CounterEpochID
	reader.mu.Lock()
	reader.interfaces[0].Received++
	reader.interfaces[0].Sent = 3 // decrease resets the epoch
	reader.mu.Unlock()
	second := collector.Collect(context.Background())
	if second.Gauges.CPUBusyRatio.Value == nil || math.Abs(*second.Gauges.CPUBusyRatio.Value-0.15) > 0.000001 {
		t.Fatalf("aggregate CPU tick delta mismatch: %+v", second.Gauges.CPUBusyRatio)
	}
	if second.NetworkObservations[0].CounterEpochID == firstEpoch {
		t.Fatal("counter decrease did not start a new epoch")
	}
	if len(second.CapabilitiesMissing) != 9 {
		t.Fatalf("explicit unsupported capability count=%d want=9", len(second.CapabilitiesMissing))
	}
	if second.ComponentTimings.CPU.MonotonicEndNS == second.ComponentTimings.Pressure.MonotonicEndNS {
		t.Fatal("host components did not retain independent timings")
	}
}

func TestPressureUnavailableUntilExactBuildQualified(t *testing.T) {
	reader := newFakeNativeReader()
	reader.osBuild = "24F75"
	reader.pressureFlag = 2
	collector, err := NewHostCollector(HostOptions{HostID: testHostID, BootID: testBootID, DataPath: t.TempDir(), Reader: reader})
	if err != nil {
		t.Fatal(err)
	}
	observation := collector.Collect(context.Background())
	if observation.Gauges.PressureLevel.Value != nil || dereference(observation.Gauges.PressureLevel.MissingReason) != domain.MissingMethodUncertified {
		t.Fatalf("uncertified OS pressure was presented as canonical: %+v", observation.Gauges.PressureLevel)
	}
	for flag, expected := range map[uint32]domain.PressureLevel{1: domain.PressureNormal, 2: domain.PressureWarning, 4: domain.PressureCritical} {
		if actual, ok := pressureLevel(flag); !ok || actual != expected {
			t.Fatalf("pressure flag %d mapped to %q valid=%v", flag, actual, ok)
		}
	}
	if _, ok := pressureLevel(3); ok {
		t.Fatal("unknown pressure bit combination accepted")
	}
}

func TestPressureQualificationIsExactBuildAllowlist(t *testing.T) {
	if !pressureMethodQualified("24F74") {
		t.Fatal("witnessed macOS 15.5 build 24F74 must be qualified")
	}
	for _, build := range []string{"", "24F73", "24F75", "24G90", "15.5"} {
		if pressureMethodQualified(build) {
			t.Fatalf("unwitnessed build %q was qualified", build)
		}
	}
}

func TestNetworkCollectionCapsInterfacesAndMarksPartial(t *testing.T) {
	reader := newFakeNativeReader()
	for index := 10; index >= 1; index-- {
		reader.interfaces = append(reader.interfaces, InterfaceCounters{Index: uint32(index), Name: fmt.Sprintf("if%d", index), Received: uint64(index), Sent: uint64(index)})
	}
	collector, err := NewHostCollector(HostOptions{HostID: testHostID, BootID: testBootID, DataPath: t.TempDir(), Reader: reader})
	if err != nil {
		t.Fatal(err)
	}
	observation := collector.Collect(context.Background())
	if len(observation.NetworkObservations) != maxNetworkInterfaces {
		t.Fatalf("network retained=%d want=%d", len(observation.NetworkObservations), maxNetworkInterfaces)
	}
	if len(observation.CapabilitiesMissing) != 11 {
		t.Fatalf("network truncation missing facts=%d want=11", len(observation.CapabilitiesMissing))
	}
	for _, item := range observation.NetworkObservations {
		if item.CounterEpochID == "" || item.ReceivedBytesTotal == nil || item.SentBytesTotal == nil {
			t.Fatalf("retained network counter incomplete: %+v", item)
		}
	}
}

func TestBlockedHostComponentDoesNotBlockOthersOrSpawnAgain(t *testing.T) {
	blocked := make(chan struct{})
	reader := newFakeNativeReader()
	reader.pressureBlock = blocked
	collector, err := NewHostCollector(HostOptions{HostID: testHostID, BootID: testBootID, DataPath: t.TempDir(), Reader: reader})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	first := collector.Collect(context.Background())
	if elapsed := time.Since(started); elapsed > 1500*time.Millisecond {
		t.Fatalf("blocked component stalled collection for %s", elapsed)
	}
	if first.Gauges.CompressedBytes.Value == nil || dereference(first.Gauges.PressureLevel.MissingReason) != domain.MissingSourceTimeout {
		t.Fatalf("independent component result lost: compressed=%+v pressure=%+v", first.Gauges.CompressedBytes, first.Gauges.PressureLevel)
	}
	_ = collector.Collect(context.Background())
	reader.mu.Lock()
	pressureCalls, buildCalls := reader.pressureCalls, reader.osBuildCalls
	reader.mu.Unlock()
	if pressureCalls != 1 || buildCalls != 0 {
		t.Fatalf("blocked native read duplicated or advanced: pressure=%d build=%d", pressureCalls, buildCalls)
	}
	close(blocked)
}

func TestBoundedCallDiscardsTimedOutWorkBeforeRetry(t *testing.T) {
	var call boundedCall[int]
	budget := newLocalCallBudget(1)
	blocked := make(chan struct{})
	var calls atomic.Int32
	read := func(context.Context) (int, error) {
		calls.Add(1)
		<-blocked
		return 7, nil
	}
	if _, err := call.invoke(context.Background(), 20*time.Millisecond, budget, "test.read", read); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked read error=%v", err)
	}
	if _, err := call.invoke(context.Background(), 20*time.Millisecond, budget, "test.read", read); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("in-flight read error=%v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("blocked read spawned %d workers", calls.Load())
	}
	close(blocked)
	deadline := time.Now().Add(time.Second)
	for calls.Load() == 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
		_, _ = call.invoke(context.Background(), 20*time.Millisecond, budget, "test.read", read)
	}
	if calls.Load() != 2 {
		t.Fatalf("completed stale read did not permit a fresh call: calls=%d", calls.Load())
	}
}

func TestLocalCallBudgetCapsConcurrentNativeWork(t *testing.T) {
	budget := newLocalCallBudget(4)
	var active, maximum atomic.Int32
	start := make(chan struct{})
	var group sync.WaitGroup
	for index := 0; index < 12; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			if !budget.Acquire(context.Background(), "test.component") {
				t.Error("budget unexpectedly rejected a live context")
				return
			}
			current := active.Add(1)
			for {
				seen := maximum.Load()
				if current <= seen || maximum.CompareAndSwap(seen, current) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
			active.Add(-1)
			budget.Release("test.component")
		}()
	}
	close(start)
	group.Wait()
	if maximum.Load() != 4 {
		t.Fatalf("maximum concurrent native calls=%d want=4", maximum.Load())
	}
}

func TestProcessCollectionCapsRanksAndDoesNotPersistNames(t *testing.T) {
	reader := newFakeNativeReader()
	for pid := 1; pid <= 520; pid++ {
		reader.pids = append(reader.pids, pid)
		reader.processes[pid] = processFixture(pid, uint64(pid), uint64(pid), uint64(pid))
		reader.processes[pid] = ProcessRead{Identity: reader.processes[pid].Identity, Name: fmt.Sprintf("secret-process-%d", pid)}
	}
	reader.pidsTruncated = true
	reader.processes[7] = processFixture(7, 7, 1, 1)
	reader.processes[7] = ProcessRead{Identity: reader.processes[7].Identity, Name: "ollama"}
	collector := newProcessCollectorForTest(t, reader, []ExpectedProcess{{PID: 7, ProcessStartIdentity: 7, TargetID: testTargetID, Role: identity.RoleSelectedOllama}})
	observation := collector.Collect(context.Background())
	if observation.Summary.EligiblePIDCount != 512 || observation.Summary.ExaminedPIDCount != 512 || !observation.Summary.EnumerationTruncated || observation.Summary.RetainedProcessCount != 32 {
		t.Fatalf("process caps not enforced: %+v", observation.Summary)
	}
	foundSelected := false
	for _, process := range observation.Processes {
		if process.PID == 7 && process.Category == domain.ProcessSelectedOllama {
			foundSelected = true
		}
	}
	if !foundSelected {
		t.Fatal("verified selected runtime was not force-retained")
	}
	encoded, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "secret-process") {
		t.Fatal("non-allowlisted process basename escaped the collector")
	}
}

func TestProcessIdentityReuseResetsCPUAndProcessKey(t *testing.T) {
	reader := newFakeNativeReader()
	reader.pids = []int{10}
	reader.processes[10] = processFixture(10, 100, 100, 50)
	collector := newProcessCollectorForTest(t, reader, nil)
	first := collector.Collect(context.Background())
	firstKey := first.Processes[0].ProcessKey
	reader.monotonic.Add(uint64(time.Second))
	reader.processes[10] = processFixture(10, 100, 500_000_100, 500_000_050)
	second := collector.Collect(context.Background())
	if second.Processes[0].CPUBusyRatio == nil || *second.Processes[0].CPUBusyRatio <= 0 {
		t.Fatalf("stable process did not gain CPU delta: %+v", second.Processes[0])
	}
	reader.monotonic.Add(uint64(time.Second))
	reader.processes[10] = processFixture(10, 101, 900_000_100, 900_000_050)
	third := collector.Collect(context.Background())
	if third.Processes[0].ProcessKey == firstKey || third.Processes[0].CPUBusyRatio != nil {
		t.Fatalf("PID reuse inherited prior identity state: %+v", third.Processes[0])
	}
}

func TestEndpointAssociationRequiresCompleteSingleVerifiedOwner(t *testing.T) {
	reader := newFakeNativeReader()
	reader.pids = []int{10, 11}
	reader.processes[10] = ProcessRead{Identity: processFixture(10, 100, 1, 1).Identity, Name: "ollama"}
	reader.processes[11] = processFixture(11, 110, 1, 1)
	reader.listeners[10] = true
	expected := []ExpectedProcess{{PID: 10, ProcessStartIdentity: 100, TargetID: testTargetID, Role: identity.RoleSelectedOllama}}
	collector := newProcessCollectorForTest(t, reader, expected)
	verified := collector.Collect(context.Background()).Association
	if verified.Quality != domain.AssociationVerified || verified.PID == nil || *verified.PID != 10 || verified.ProcessStartIdentity == nil || string(*verified.ProcessStartIdentity) != "100" || verified.ProcessKey == nil {
		t.Fatalf("single verified listener association failed: %+v", verified)
	}

	reader.listeners[11] = true
	multiple := collector.Collect(context.Background()).Association
	if multiple.Quality != domain.AssociationAmbiguous || dereference(multiple.Reason) != domain.MissingIdentityUnverified {
		t.Fatalf("ambiguous owners were accepted: %+v", multiple)
	}
	reader.listeners[11] = false
	reader.processErrors[11] = ErrPermissionDenied
	denied := collector.Collect(context.Background())
	if denied.Association.Quality != domain.AssociationDeclaredUnverified || denied.Summary.PermissionDeniedCount != 1 || denied.Summary.Coverage != "partial" {
		t.Fatalf("denied population was treated as exhaustive: %+v %+v", denied.Association, denied.Summary)
	}
}

func TestVerifiedSelectedExitRequiresExhaustiveExactIdentityAbsence(t *testing.T) {
	reader := newFakeNativeReader()
	reader.pids = []int{10}
	reader.processes[10] = ProcessRead{Identity: processFixture(10, 100, 1, 1).Identity, Name: "ollama"}
	reader.listeners[10] = true
	collector := newProcessCollectorForTest(t, reader, nil)
	first := collector.Collect(context.Background())
	if first.Association.ProcessKey == nil {
		t.Fatalf("initial listener identity=%+v", first.Association)
	}
	pinned := ExpectedProcess{PID: 10, ProcessStartIdentity: 100, ProcessKey: *first.Association.ProcessKey, LastSeenMS: first.Timing.ObservedWallMS, TargetID: testTargetID, Role: identity.RoleSelectedOllama}
	collector.SetExpected([]ExpectedProcess{pinned})

	reader.processes[10] = ProcessRead{Identity: processFixture(10, 101, 2, 2).Identity, Name: "ollama"}
	reused := collector.Collect(context.Background())
	if reused.Association.VerifiedExit != nil {
		t.Fatalf("PID reuse was treated as verified exit: %+v", reused.Association.VerifiedExit)
	}

	reader.processErrors[10] = ErrPermissionDenied
	partial := collector.Collect(context.Background())
	if partial.Association.VerifiedExit != nil || partial.Summary.Coverage != "partial" {
		t.Fatalf("partial scan claimed exit: %+v %+v", partial.Association, partial.Summary)
	}

	delete(reader.processErrors, 10)
	reader.pids = []int{}
	exited := collector.Collect(context.Background())
	if exited.Association.VerifiedExit == nil || exited.Association.VerifiedExit.ProcessKey != pinned.ProcessKey || exited.Association.VerifiedExit.ProcessStartIdentity != "100" || exited.Association.VerifiedExit.LastSeenMS != pinned.LastSeenMS {
		t.Fatalf("exhaustive absence did not retain exact verified identity: %+v", exited.Association.VerifiedExit)
	}
}

func TestSelectedProcessPinCannotCrossTargetScope(t *testing.T) {
	reader := newFakeNativeReader()
	reader.pids = []int{10}
	reader.processes[10] = ProcessRead{Identity: processFixture(10, 100, 1, 1).Identity, Name: "ollama"}
	foreignPin := ExpectedProcess{PID: 10, ProcessStartIdentity: 100, ProcessKey: strings.Repeat("f", 64), LastSeenMS: 1, TargetID: "44444444-4444-4444-8444-444444444444", Role: identity.RoleSelectedOllama}
	collector := newProcessCollectorForTest(t, reader, []ExpectedProcess{foreignPin})
	observed := collector.Collect(context.Background())
	if observed.Processes[0].Category != domain.ProcessOtherSameUser || observed.Processes[0].TargetID != nil || observed.Processes[0].AssociationQuality != domain.AssociationNone || observed.Association.VerifiedExit != nil {
		t.Fatalf("foreign target pin changed process identity: process=%+v association=%+v", observed.Processes[0], observed.Association)
	}
	reader.pids = []int{}
	absent := collector.Collect(context.Background())
	if absent.Association.VerifiedExit != nil {
		t.Fatalf("foreign target absence claimed exit: %+v", absent.Association.VerifiedExit)
	}
}

func TestRankProcessesInterleavesCPUAndFootprintDeterministically(t *testing.T) {
	values := make([]rankedProcess, 0, 40)
	for pid := 1; pid <= 40; pid++ {
		cpu := float64(pid) / 100
		footprint := domain.DecimalUint64(uint64(1000 - pid))
		values = append(values, rankedProcess{observation: domain.ProcessObservation{PID: pid, ProcessKey: fmt.Sprintf("key-%d", pid), CPUBusyRatio: &cpu, PhysicalFootprintBytes: &footprint}, forced: pid == 20})
	}
	retained := rankProcesses(values, 8)
	got := make([]int, 0, len(retained))
	for _, value := range retained {
		got = append(got, value.PID)
	}
	want := []int{20, 40, 1, 39, 2, 38, 3, 37}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("rank order=%v want=%v", got, want)
	}
}

func newProcessCollectorForTest(t *testing.T, reader NativeReader, expected []ExpectedProcess) *ProcessCollector {
	t.Helper()
	scope := identity.Scope{HostID: testHostID, BootID: testBootID}
	copy(scope.Salt[:], strings.Repeat("s", identity.SaltBytes))
	collector, err := NewProcessCollector(ProcessOptions{
		HostID: testHostID, BootID: testBootID, TargetID: testTargetID, Endpoint: "127.0.0.1:11434", EndpointHash: strings.Repeat("a", 64), Scope: scope,
		Expected: expected, SampleInterval: time.Second, Reader: reader,
	})
	if err != nil {
		t.Fatal(err)
	}
	return collector
}

func processFixture(pid int, start, userNS, systemNS uint64) ProcessRead {
	return ProcessRead{Identity: identity.ProcessIdentity{
		PID: pid, UID: 501, ParentPID: 1, StartAbsolute: start, StartWallSec: start, UserTimeNS: userNS, SystemTimeNS: systemNS, PhysicalFootprint: uint64(pid) * 4096,
	}, Name: fmt.Sprintf("process-%d", pid)}
}

func dereference[T any](value *T) T {
	var zero T
	if value == nil {
		return zero
	}
	return *value
}
