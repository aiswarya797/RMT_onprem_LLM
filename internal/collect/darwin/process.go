package darwin

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"rmt.local/monitor/internal/collect/identity"
	"rmt.local/monitor/internal/domain"
)

const (
	maxExaminedProcesses = 512
	maxRetainedProcesses = 32
	processScanTimeout   = 2 * time.Second
	processMethod        = "darwin-proc-rusage-candidate-1"
)

type ExpectedProcess struct {
	PID                  int
	ProcessStartIdentity uint64
	ProcessKey           string
	LastSeenMS           int64
	TargetID             string
	Role                 identity.VerifiedRole
}

type ProcessOptions struct {
	HostID         string
	BootID         string
	TargetID       string
	Endpoint       string
	EndpointHash   string
	Scope          identity.Scope
	Expected       []ExpectedProcess
	SampleInterval time.Duration
	Reader         NativeReader
	Clock          func() time.Time
	CallBudget     CallBudget
}

type ProcessCollector struct {
	options  ProcessOptions
	mu       sync.Mutex
	last     map[string]processCPUState
	scanCall boundedCall[processScanResult]
}

type processCPUState struct {
	userNS      uint64
	systemNS    uint64
	monotonicNS uint64
}

type rankedProcess struct {
	observation domain.ProcessObservation
	forced      bool
}

type processScanResult struct {
	collection domain.ProcessCollection
	nextCPU    map[string]processCPUState
}

func NewProcessCollector(options ProcessOptions) (*ProcessCollector, error) {
	if options.HostID == "" || options.BootID == "" || options.Scope.HostID != options.HostID || options.Scope.BootID != options.BootID {
		return nil, errors.New("process collector requires matching host and boot identity scope")
	}
	if options.SampleInterval < time.Second || options.SampleInterval > time.Minute {
		return nil, errors.New("process sample interval must be between 1s and 60s")
	}
	if options.TargetID != "" {
		decoded, err := hex.DecodeString(options.EndpointHash)
		if err != nil || len(decoded) != 32 {
			return nil, errors.New("process collector requires the configured endpoint selector hash")
		}
	}
	if options.Reader == nil {
		options.Reader = NewNativeReader()
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	if options.CallBudget == nil {
		options.CallBudget = newLocalCallBudget(4)
	}
	return &ProcessCollector{options: options, last: make(map[string]processCPUState)}, nil
}

func (collector *ProcessCollector) Collect(ctx context.Context) domain.ProcessCollection {
	collector.mu.Lock()
	previousCPU := make(map[string]processCPUState, len(collector.last))
	for key, value := range collector.last {
		previousCPU[key] = value
	}
	expected := append([]ExpectedProcess(nil), collector.options.Expected...)
	collector.mu.Unlock()
	result, err := collector.scanCall.invoke(ctx, processScanTimeout, collector.options.CallBudget, "process.scan", func(scanCtx context.Context) (processScanResult, error) {
		return collector.collectSync(scanCtx, previousCPU, expected), nil
	})
	if err != nil {
		now := collector.options.Clock()
		monotonic := collector.options.Reader.MonotonicNS()
		association := domain.EndpointAssociation{TargetID: collector.options.TargetID, EndpointHash: collector.options.EndpointHash, Quality: domain.AssociationNone, Provenance: nativeProvenance(processMethod, now.UnixMilli())}
		if collector.options.TargetID != "" {
			reason := missingReason(err)
			association.Quality, association.Reason = domain.AssociationDeclaredUnverified, &reason
		}
		return domain.ProcessCollection{
			Timing: domain.NewComponentTiming(now, monotonic, monotonic), Processes: []domain.ProcessObservation{}, Association: association,
			Summary: domain.ProcessSummary{Coverage: "partial", MethodRevision: processMethod, SampleIntervalMS: collector.options.SampleInterval.Milliseconds(), ScanDurationMS: 0},
		}
	}
	collector.mu.Lock()
	collector.last = result.nextCPU
	collector.mu.Unlock()
	return result.collection
}

func (collector *ProcessCollector) SetExpected(values []ExpectedProcess) {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	collector.options.Expected = append([]ExpectedProcess(nil), values...)
}

func (collector *ProcessCollector) collectSync(ctx context.Context, previousCPU map[string]processCPUState, expectedValues []ExpectedProcess) processScanResult {

	startNS := collector.options.Reader.MonotonicNS()
	startWall := collector.options.Clock()
	scanCtx, cancel := context.WithTimeout(ctx, processScanTimeout)
	defer cancel()
	pids, enumerationTruncated, listErr := collector.options.Reader.SameUserPIDs(scanCtx, maxExaminedProcesses)
	sort.Ints(pids)
	if len(pids) > maxExaminedProcesses {
		pids = pids[:maxExaminedProcesses]
		enumerationTruncated = true
	}

	expected := make(map[int]ExpectedProcess, len(expectedValues))
	for _, item := range expectedValues {
		if item.Role == identity.RoleSelectedOllama && (item.TargetID == "" || item.TargetID != collector.options.TargetID) {
			continue
		}
		if item.PID > 0 && item.ProcessStartIdentity != 0 {
			expected[item.PID] = item
		}
	}
	observed := make([]rankedProcess, 0, len(pids))
	allReads := make([]ProcessRead, 0, len(pids))
	denied := 0
	examined := 0
	partial := listErr != nil || enumerationTruncated
	nowNS := collector.options.Reader.MonotonicNS()
	nextCPU := make(map[string]processCPUState, len(pids))
	for _, pid := range pids {
		if scanCtx.Err() != nil {
			partial = true
			break
		}
		examined++
		value, err := collector.options.Reader.Process(scanCtx, pid)
		if err != nil {
			partial = true
			if errors.Is(err, ErrPermissionDenied) {
				denied++
			}
			continue
		}
		allReads = append(allReads, value)
		key, err := identity.ProcessKey(collector.options.Scope, value.Identity)
		if err != nil {
			partial = true
			continue
		}
		role := identity.RoleNone
		forced := false
		if wanted, ok := expected[pid]; ok && wanted.ProcessStartIdentity == value.Identity.StartAbsolute {
			role = wanted.Role
			forced = role == identity.RoleSelectedOllama || role == identity.RoleRMTHub || role == identity.RoleRMTCollector
		}
		display, category := identity.DisplayIdentity(value.Name, role)
		observation := domain.ProcessObservation{
			HostID: collector.options.HostID, BootID: collector.options.BootID, PID: pid,
			ProcessStartIdentity: domain.DecimalUint64(value.Identity.StartAbsolute), ProcessKey: key,
			DisplayBasename: display, Category: category, AssociationQuality: domain.AssociationNone,
			Missing: []domain.MissingCapability{}, Provenance: nativeProvenance(processMethod, startWall.UnixMilli()),
		}
		footprint := domain.DecimalUint64(value.Identity.PhysicalFootprint)
		observation.PhysicalFootprintBytes = &footprint
		currentCPU := processCPUState{userNS: value.Identity.UserTimeNS, systemNS: value.Identity.SystemTimeNS, monotonicNS: nowNS}
		if previous, ok := previousCPU[key]; ok {
			observation.CPUBusyRatio = processCPURatio(previous, currentCPU, collector.options.Reader.LogicalCPUCount())
		}
		if observation.CPUBusyRatio == nil {
			observation.Missing = append(observation.Missing, missing("process.cpu.busy_ratio", domain.MissingCollectionGap, "process_interval_unavailable"))
		}
		nextCPU[key] = currentCPU
		observed = append(observed, rankedProcess{observation: observation, forced: forced})
	}

	association := collector.associateEndpoint(scanCtx, allReads, expected, !partial && denied == 0 && examined == len(pids), startWall.UnixMilli())
	for index := range observed {
		wanted, ok := expected[observed[index].observation.PID]
		if ok && wanted.Role == identity.RoleSelectedOllama && wanted.ProcessStartIdentity == uint64FromDecimal(observed[index].observation.ProcessStartIdentity) && collector.options.TargetID != "" {
			observed[index].observation.TargetID = &collector.options.TargetID
			observed[index].observation.AssociationQuality = domain.AssociationDeclaredUnverified
		}
		if association.Quality == domain.AssociationVerified && association.PID != nil && association.ProcessStartIdentity != nil && association.ProcessKey != nil && observed[index].observation.PID == *association.PID && observed[index].observation.ProcessStartIdentity == *association.ProcessStartIdentity && observed[index].observation.ProcessKey == *association.ProcessKey {
			observed[index].forced = true
		}
	}
	retained := rankProcesses(observed, maxRetainedProcesses)
	endNS := collector.options.Reader.MonotonicNS()
	endWall := collector.options.Clock()
	durationMS := int64(0)
	if endNS >= startNS {
		durationMS = int64((endNS - startNS) / uint64(time.Millisecond))
	}
	if durationMS > processScanTimeout.Milliseconds() {
		durationMS = processScanTimeout.Milliseconds()
		partial = true
	}
	if scanCtx.Err() != nil {
		partial = true
	}
	coverage := "complete"
	if partial || denied > 0 {
		coverage = "partial"
	}
	return processScanResult{collection: domain.ProcessCollection{
		Timing:    domain.NewComponentTiming(startWall.Add(endWall.Sub(startWall)/2), startNS, endNS),
		Processes: retained,
		Summary: domain.ProcessSummary{
			EligiblePIDCount: min(len(pids), maxExaminedProcesses), ExaminedPIDCount: min(examined, maxExaminedProcesses), PermissionDeniedCount: min(denied, maxExaminedProcesses),
			RetainedProcessCount: len(retained), EnumerationTruncated: enumerationTruncated, Coverage: coverage, MethodRevision: processMethod,
			SampleIntervalMS: collector.options.SampleInterval.Milliseconds(), ScanDurationMS: durationMS,
		},
		Association: association,
	}, nextCPU: nextCPU}
}

func processCPURatio(previous, current processCPUState, logicalCPUs int) *float64 {
	if logicalCPUs < 1 || current.monotonicNS <= previous.monotonicNS || current.userNS < previous.userNS || current.systemNS < previous.systemNS {
		return nil
	}
	used, ok := checkedAdd(current.userNS-previous.userNS, current.systemNS-previous.systemNS)
	if !ok {
		return nil
	}
	capacity := current.monotonicNS - previous.monotonicNS
	if capacity > ^uint64(0)/uint64(logicalCPUs) {
		return nil
	}
	capacity *= uint64(logicalCPUs)
	value := float64(used) / float64(capacity)
	if value < 0 {
		return nil
	}
	if value > 1 {
		value = 1
	}
	return &value
}

func rankProcesses(values []rankedProcess, limit int) []domain.ProcessObservation {
	if limit <= 0 {
		return []domain.ProcessObservation{}
	}
	result := make([]domain.ProcessObservation, 0, min(limit, len(values)))
	seen := make(map[string]struct{}, len(values))
	add := func(value rankedProcess) {
		if len(result) >= limit {
			return
		}
		if _, ok := seen[value.observation.ProcessKey]; ok {
			return
		}
		seen[value.observation.ProcessKey] = struct{}{}
		result = append(result, value.observation)
	}
	forced := append([]rankedProcess(nil), values...)
	sort.SliceStable(forced, func(i, j int) bool {
		if forced[i].forced != forced[j].forced {
			return forced[i].forced
		}
		return forced[i].observation.PID < forced[j].observation.PID
	})
	for _, value := range forced {
		if value.forced {
			add(value)
		}
	}
	cpuRank := append([]rankedProcess(nil), values...)
	sort.SliceStable(cpuRank, func(i, j int) bool {
		left, right := cpuRank[i].observation.CPUBusyRatio, cpuRank[j].observation.CPUBusyRatio
		if left == nil || right == nil {
			return left != nil
		}
		if *left == *right {
			return cpuRank[i].observation.PID < cpuRank[j].observation.PID
		}
		return *left > *right
	})
	footprintRank := append([]rankedProcess(nil), values...)
	sort.SliceStable(footprintRank, func(i, j int) bool {
		left, right := footprintRank[i].observation.PhysicalFootprintBytes, footprintRank[j].observation.PhysicalFootprintBytes
		if left == nil || right == nil {
			return left != nil
		}
		leftValue, _ := strconv.ParseUint(string(*left), 10, 64)
		rightValue, _ := strconv.ParseUint(string(*right), 10, 64)
		if leftValue == rightValue {
			return footprintRank[i].observation.PID < footprintRank[j].observation.PID
		}
		return leftValue > rightValue
	})
	for index := 0; len(result) < limit && index < len(values); index++ {
		add(cpuRank[index])
		add(footprintRank[index])
	}
	return result
}

func (collector *ProcessCollector) associateEndpoint(ctx context.Context, reads []ProcessRead, expected map[int]ExpectedProcess, exhaustive bool, observedMS int64) domain.EndpointAssociation {
	result := domain.EndpointAssociation{TargetID: collector.options.TargetID, EndpointHash: collector.options.EndpointHash, Quality: domain.AssociationNone, Provenance: nativeProvenance(processMethod, observedMS)}
	if collector.options.TargetID == "" || collector.options.Endpoint == "" {
		return result
	}
	if exhaustive {
		for _, wanted := range expected {
			if wanted.Role != identity.RoleSelectedOllama || wanted.TargetID != collector.options.TargetID || wanted.ProcessKey == "" || wanted.LastSeenMS < 0 {
				continue
			}
			pidPresent := false
			for _, value := range reads {
				if value.Identity.PID == wanted.PID {
					pidPresent = true
					break
				}
			}
			if !pidPresent {
				result.VerifiedExit = &domain.VerifiedProcessExit{PID: wanted.PID, ProcessStartIdentity: domain.DecimalUint64(wanted.ProcessStartIdentity), ProcessKey: wanted.ProcessKey, LastSeenMS: wanted.LastSeenMS}
			}
			break
		}
	}
	if !exhaustive {
		reason := domain.MissingIdentityUnverified
		result.Quality, result.Reason = domain.AssociationDeclaredUnverified, &reason
		return result
	}
	host, portText, err := net.SplitHostPort(collector.options.Endpoint)
	portValue, portErr := strconv.ParseUint(portText, 10, 16)
	ip := net.ParseIP(host)
	if err != nil || portErr != nil || (host != "localhost" && (ip == nil || !ip.IsLoopback())) || portValue == 0 {
		reason := domain.MissingIdentityUnverified
		result.Quality, result.Reason = domain.AssociationDeclaredUnverified, &reason
		return result
	}
	owners := make([]ProcessRead, 0, 2)
	unknown := false
	for _, value := range reads {
		listens, listenErr := collector.options.Reader.PIDListensOnEndpoint(ctx, value.Identity.PID, value.Identity.StartAbsolute, host, uint16(portValue))
		if listenErr != nil {
			unknown = true
			continue
		}
		if listens {
			owners = append(owners, value)
		}
	}
	if unknown {
		reason := domain.MissingIdentityUnverified
		result.Quality, result.Reason = domain.AssociationDeclaredUnverified, &reason
		return result
	}
	if len(owners) > 1 {
		reason := domain.MissingIdentityUnverified
		result.Quality, result.Reason = domain.AssociationAmbiguous, &reason
		return result
	}
	if len(owners) == 0 {
		reason := domain.MissingIdentityUnverified
		result.Quality, result.Reason = domain.AssociationDeclaredUnverified, &reason
		return result
	}
	owner := owners[0]
	key, err := identity.ProcessKey(collector.options.Scope, owner.Identity)
	if err != nil {
		reason := domain.MissingIdentityUnverified
		result.Quality, result.Reason = domain.AssociationDeclaredUnverified, &reason
		return result
	}
	pid, start := owner.Identity.PID, domain.DecimalUint64(owner.Identity.StartAbsolute)
	result.PID, result.ProcessStartIdentity, result.ProcessKey = &pid, &start, &key
	result.Quality = domain.AssociationVerified
	return result
}

func uint64FromDecimal(value domain.Uint64Decimal) uint64 {
	parsed, _ := strconv.ParseUint(string(value), 10, 64)
	return parsed
}
