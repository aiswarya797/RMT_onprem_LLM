package darwin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"rmt.local/monitor/internal/domain"
)

const (
	hostComponentTimeout = time.Second
	maxNetworkInterfaces = 8
	pressureMethod       = "xnu-11417.121.6-pressure-flags"
	cpuMethod            = "darwin-host-cpu-candidate-1"
	compressedMethod     = "darwin-vm-candidate-1"
	swapMethod           = "darwin-swap-candidate-1"
	diskMethod           = "darwin-statfs-candidate-1"
	networkMethod        = "darwin-net-rt-iflist2-ifdata64-candidate-1"
	pressureSourceSHA256 = "552451e0067fd7ee3b70242f53bc87b87566cfdca72f2c66d1f97895668f38e8"
)

// pressureQualifiedBuilds is intentionally an exact-build allowlist. The
// 24F74 mapping was witnessed against an independent sysctl read in
// TestNativePressureMethodWitness; a macOS release family match is not enough.
var pressureQualifiedBuilds = map[string]struct{}{
	"24F74": {},
}

func pressureMethodQualified(osBuild string) bool {
	_, ok := pressureQualifiedBuilds[osBuild]
	return ok
}

type HostOptions struct {
	HostID            string
	BootID            string
	DataPath          string
	Reader            NativeReader
	Clock             func() time.Time
	NewUUID           func() (string, error)
	PressureQualified func(osBuild string) bool
	CallBudget        CallBudget
}

type HostCollector struct {
	options        HostOptions
	mu             sync.Mutex
	lastCPU        *CPUTicks
	epochs         map[string]counterState
	cpuCall        boundedCall[CPUTicks]
	pressureCall   boundedCall[pressureRead]
	compressedCall boundedCall[uint64]
	swapCall       boundedCall[uint64]
	diskCall       boundedCall[uint64]
	networkCall    boundedCall[interfaceRead]
}

type counterState struct {
	bootID string
	epoch  string
	rx     uint64
	tx     uint64
}

type pressureRead struct {
	flag    uint32
	osBuild string
}

func NewHostCollector(options HostOptions) (*HostCollector, error) {
	if options.HostID == "" || options.BootID == "" || options.DataPath == "" {
		return nil, errors.New("host collector requires host, boot and configured data path")
	}
	if options.Reader == nil {
		options.Reader = NewNativeReader()
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	if options.NewUUID == nil {
		options.NewUUID = domain.NewUUID
	}
	if options.PressureQualified == nil {
		options.PressureQualified = pressureMethodQualified
	}
	if options.CallBudget == nil {
		options.CallBudget = newLocalCallBudget(4)
	}
	return &HostCollector{options: options, epochs: make(map[string]counterState)}, nil
}

func (collector *HostCollector) Collect(ctx context.Context) domain.HostObservation {
	collector.mu.Lock()
	defer collector.mu.Unlock()

	type result struct {
		cpu              domain.MetricObservation[float64]
		cpuTiming        domain.ComponentTiming
		pressure         domain.MetricObservation[domain.PressureLevel]
		pressureTiming   domain.ComponentTiming
		compressed       domain.MetricObservation[domain.Uint64Decimal]
		compressedTiming domain.ComponentTiming
		swap             domain.MetricObservation[domain.Uint64Decimal]
		swapTiming       domain.ComponentTiming
		disk             domain.MetricObservation[domain.Uint64Decimal]
		diskTiming       domain.ComponentTiming
		network          []domain.NetworkObservation
		networkTiming    domain.ComponentTiming
		networkMissing   []domain.MissingCapability
	}
	var values result
	var group sync.WaitGroup
	group.Add(6)
	go func() { defer group.Done(); values.cpu, values.cpuTiming = collector.collectCPU(ctx) }()
	go func() { defer group.Done(); values.pressure, values.pressureTiming = collector.collectPressure(ctx) }()
	go func() {
		defer group.Done()
		values.compressed, values.compressedTiming = collector.collectBytes(ctx, compressedMethod, &collector.compressedCall, collector.options.Reader.CompressedBytes)
	}()
	go func() {
		defer group.Done()
		values.swap, values.swapTiming = collector.collectBytes(ctx, swapMethod, &collector.swapCall, collector.options.Reader.SwapUsedBytes)
	}()
	go func() {
		defer group.Done()
		values.disk, values.diskTiming = collector.collectBytes(ctx, diskMethod, &collector.diskCall, func(callCtx context.Context) (uint64, error) {
			return collector.options.Reader.DiskAvailableBytes(callCtx, collector.options.DataPath)
		})
	}()
	go func() {
		defer group.Done()
		values.network, values.networkTiming, values.networkMissing = collector.collectNetwork(ctx)
	}()
	group.Wait()
	missing := append(unsupportedDarwinCapabilities(), values.networkMissing...)
	return domain.HostObservation{
		ComponentTimings:    domain.HostComponentTimings{CPU: values.cpuTiming, Pressure: values.pressureTiming, Compressed: values.compressedTiming, Swap: values.swapTiming, Disk: values.diskTiming, Network: values.networkTiming},
		Gauges:              domain.HostGauges{CPUBusyRatio: values.cpu, PressureLevel: values.pressure, CompressedBytes: values.compressed, SwapUsedBytes: values.swap, DiskFreeBytes: values.disk},
		NetworkObservations: values.network,
		CapabilitiesMissing: missing,
	}
}

func (collector *HostCollector) collectCPU(ctx context.Context) (domain.MetricObservation[float64], domain.ComponentTiming) {
	value, timing, err := timedRead(ctx, collector.options, "host.cpu", &collector.cpuCall, collector.options.Reader.HostCPUTicks)
	provenance := nativeProvenance(cpuMethod, timing.ObservedWallMS)
	if err != nil {
		return domain.Unavailable[float64](missingReason(err), provenance), timing
	}
	previous := collector.lastCPU
	collector.lastCPU = &value
	if previous == nil {
		return domain.Unavailable[float64](domain.MissingCollectionGap, provenance), timing
	}
	busyBefore, totalBefore, beforeOK := cpuTotals(*previous)
	busyAfter, totalAfter, afterOK := cpuTotals(value)
	if !beforeOK || !afterOK {
		return domain.Unavailable[float64](domain.MissingParseRejected, provenance), timing
	}
	if busyAfter < busyBefore || totalAfter <= totalBefore {
		return domain.Unavailable[float64](domain.MissingCollectionGap, provenance), timing
	}
	ratio := float64(busyAfter-busyBefore) / float64(totalAfter-totalBefore)
	if ratio < 0 || ratio > 1 {
		return domain.Unavailable[float64](domain.MissingParseRejected, provenance), timing
	}
	return domain.Measured(ratio, provenance), timing
}

func cpuTotals(value CPUTicks) (uint64, uint64, bool) {
	busy, ok := checkedAdd(value.User, value.System)
	if !ok {
		return 0, 0, false
	}
	busy, ok = checkedAdd(busy, value.Nice)
	if !ok {
		return 0, 0, false
	}
	total, ok := checkedAdd(busy, value.Idle)
	return busy, total, ok
}

func checkedAdd(left, right uint64) (uint64, bool) {
	if left > ^uint64(0)-right {
		return 0, false
	}
	return left + right, true
}

func (collector *HostCollector) collectPressure(ctx context.Context) (domain.MetricObservation[domain.PressureLevel], domain.ComponentTiming) {
	value, timing, err := timedRead(ctx, collector.options, "host.pressure", &collector.pressureCall, func(callCtx context.Context) (pressureRead, error) {
		flag, readErr := collector.options.Reader.MemoryPressureFlag(callCtx)
		if readErr != nil {
			return pressureRead{}, readErr
		}
		build, readErr := collector.options.Reader.OSBuild(callCtx)
		return pressureRead{flag: flag, osBuild: build}, readErr
	})
	provenance := nativeProvenance(pressureMethod, timing.ObservedWallMS)
	provenance.SourceArtifactSHA256 = pointer(pressureSourceSHA256)
	if err != nil {
		return domain.Unavailable[domain.PressureLevel](missingReason(err), provenance), timing
	}
	if !collector.options.PressureQualified(value.osBuild) {
		return domain.Unavailable[domain.PressureLevel](domain.MissingMethodUncertified, provenance), timing
	}
	level, ok := pressureLevel(value.flag)
	if !ok {
		return domain.Unavailable[domain.PressureLevel](domain.MissingParseRejected, provenance), timing
	}
	return domain.Measured(level, provenance), timing
}

func pressureLevel(flag uint32) (domain.PressureLevel, bool) {
	switch flag {
	case 1:
		return domain.PressureNormal, true
	case 2:
		return domain.PressureWarning, true
	case 4:
		return domain.PressureCritical, true
	default:
		return "", false
	}
}

func (collector *HostCollector) collectBytes(ctx context.Context, method string, call *boundedCall[uint64], read func(context.Context) (uint64, error)) (domain.MetricObservation[domain.Uint64Decimal], domain.ComponentTiming) {
	value, timing, err := timedRead(ctx, collector.options, "host."+method, call, read)
	provenance := nativeProvenance(method, timing.ObservedWallMS)
	if err != nil {
		return domain.Unavailable[domain.Uint64Decimal](missingReason(err), provenance), timing
	}
	return domain.Measured(domain.DecimalUint64(value), provenance), timing
}

func (collector *HostCollector) collectNetwork(ctx context.Context) ([]domain.NetworkObservation, domain.ComponentTiming, []domain.MissingCapability) {
	interfaces, timing, err := timedRead(ctx, collector.options, "host.network", &collector.networkCall, func(callCtx context.Context) (interfaceRead, error) {
		values, truncated, readErr := collector.options.Reader.Interfaces(callCtx)
		return interfaceRead{value: values, truncated: truncated}, readErr
	})
	if err != nil {
		return []domain.NetworkObservation{}, timing, []domain.MissingCapability{missing("host.network.received_bytes_total", missingReason(err), "network_read_failed"), missing("host.network.sent_bytes_total", missingReason(err), "network_read_failed")}
	}
	values := interfaces.value
	sort.Slice(values, func(i, j int) bool {
		if values[i].Index == values[j].Index {
			return values[i].Name < values[j].Name
		}
		return values[i].Index < values[j].Index
	})
	missingValues := []domain.MissingCapability{}
	if interfaces.truncated || len(values) > maxNetworkInterfaces {
		missingValues = append(missingValues, missing("host.network.received_bytes_total", domain.MissingLimitExceeded, "interface_cap"), missing("host.network.sent_bytes_total", domain.MissingLimitExceeded, "interface_cap"))
	}
	if len(values) > maxNetworkInterfaces {
		values = values[:maxNetworkInterfaces]
	}
	result := make([]domain.NetworkObservation, 0, len(values))
	for _, item := range values {
		interfaceID := collector.interfaceID(item.Name)
		epoch, epochErr := collector.counterEpoch(interfaceID, item.Received, item.Sent)
		if epochErr != nil {
			missingValues = append(missingValues, missing("host.network.received_bytes_total", domain.MissingSourceUnreachable, "epoch_unavailable"), missing("host.network.sent_bytes_total", domain.MissingSourceUnreachable, "epoch_unavailable"))
			continue
		}
		rx, tx := domain.DecimalUint64(item.Received), domain.DecimalUint64(item.Sent)
		result = append(result, domain.NetworkObservation{InterfaceID: interfaceID, BootID: collector.options.BootID, CounterEpochID: epoch, Loopback: item.Loopback, ReceivedBytesTotal: &rx, SentBytesTotal: &tx, Missing: []domain.MissingCapability{}, Provenance: nativeProvenance(networkMethod, timing.ObservedWallMS)})
	}
	return result, timing, missingValues
}

type interfaceRead struct {
	value     []InterfaceCounters
	truncated bool
}

func (collector *HostCollector) counterEpoch(interfaceID string, rx, tx uint64) (string, error) {
	previous, exists := collector.epochs[interfaceID]
	if !exists || previous.bootID != collector.options.BootID || rx < previous.rx || tx < previous.tx {
		epoch, err := collector.options.NewUUID()
		if err != nil {
			return "", err
		}
		previous = counterState{bootID: collector.options.BootID, epoch: epoch}
	}
	previous.rx, previous.tx = rx, tx
	collector.epochs[interfaceID] = previous
	return previous.epoch, nil
}

func (collector *HostCollector) interfaceID(name string) string {
	digest := sha256.Sum256([]byte("rmt-interface-v1\x00" + collector.options.HostID + "\x00" + name))
	return hex.EncodeToString(digest[:])
}

func unsupportedDarwinCapabilities() []domain.MissingCapability {
	ids := []string{"gpu.busy_ratio", "gpu.power_watts", "gpu.temperature_celsius", "gpu.process_memory_bytes", "runtime.queue_depth", "runtime.active_requests", "runtime.cache_hit_ratio", "request.passive.first_byte_ms", "request.passive.total_ms"}
	result := make([]domain.MissingCapability, 0, len(ids))
	for _, id := range ids {
		result = append(result, missing(id, domain.MissingUnsupportedPlatform, "macos_ollama_boundary"))
	}
	return result
}

func nativeProvenance(method string, observedAtMS int64) domain.Provenance {
	return domain.Provenance{Source: domain.ProvenanceDarwinAPI, MethodRevision: method, Verification: domain.VerificationDirectCapture, ObservedAtMS: &observedAtMS}
}

func missing(id string, reason domain.MissingReason, detail string) domain.MissingCapability {
	return domain.MissingCapability{ID: id, Reason: reason, DetailCode: &detail}
}

func pointer[T any](value T) *T { return &value }

func missingReason(err error) domain.MissingReason {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return domain.MissingSourceTimeout
	case errors.Is(err, ErrPermissionDenied):
		return domain.MissingPermissionDenied
	case errors.Is(err, ErrLimitExceeded):
		return domain.MissingLimitExceeded
	case errors.Is(err, ErrIdentityChanged), errors.Is(err, ErrProcessExited):
		return domain.MissingIdentityUnverified
	case errors.Is(err, ErrUnsupported):
		return domain.MissingUnsupportedPlatform
	default:
		return domain.MissingParseRejected
	}
}

func timedRead[T any](ctx context.Context, options HostOptions, component string, call *boundedCall[T], read func(context.Context) (T, error)) (T, domain.ComponentTiming, error) {
	var zero T
	startNS := options.Reader.MonotonicNS()
	startWall := options.Clock()
	value, err := call.invoke(ctx, hostComponentTimeout, options.CallBudget, component, read)
	endNS := options.Reader.MonotonicNS()
	endWall := options.Clock()
	timing := domain.NewComponentTiming(startWall.Add(endWall.Sub(startWall)/2), startNS, endNS)
	if err != nil {
		return zero, timing, err
	}
	return value, timing, nil
}

func (collector *HostCollector) String() string {
	return fmt.Sprintf("Darwin host collector %s/%s", collector.options.HostID, collector.options.BootID)
}
