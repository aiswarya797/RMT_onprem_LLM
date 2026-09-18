package scheduler

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	adapter "rmt.local/monitor/internal/adapters/ollama"
	"rmt.local/monitor/internal/collect/darwin"
	"rmt.local/monitor/internal/collect/identity"
	collectollama "rmt.local/monitor/internal/collect/ollama"
	"rmt.local/monitor/internal/collector/pairing"
	"rmt.local/monitor/internal/collector/spool"
	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
	"rmt.local/monitor/internal/store"
)

const (
	hostInterval         = 5 * time.Second
	processInterval      = 15 * time.Second
	inventoryInterval    = 30 * time.Second
	timeExchangeInterval = 60 * time.Second
)

var errCollectionDisabled = errors.New("collection disabled")

type sourceHealth struct {
	state          string
	lastSuccessMS  *int64
	firstFailureMS *int64
	failureReason  *domain.MissingReason
	failureCount   int64
}

type collectorTransport interface {
	Pair(context.Context, string, string) error
	Activate(context.Context, protocol.SessionActivation) (protocol.SessionResult, error)
	Inventory(context.Context, protocol.CollectorInventory) (protocol.InventoryResult, error)
	Batch(context.Context, protocol.CollectorBatch) (protocol.BatchACK, error)
	SourceStatus(context.Context, protocol.SourceStatus) (protocol.StatusACK, error)
	Time(context.Context) (int64, error)
	HubProcessIdentity(context.Context) (int, uint64, bool, error)
	Close()
}

type credentialMaintainer interface {
	MaintainCredential(context.Context) error
}

type CollectorStatus struct {
	SchemaVersion        string  `json:"schema_version"`
	Service              string  `json:"service"`
	State                string  `json:"state"`
	TargetState          string  `json:"target_state"`
	CollectionStarted    bool    `json:"collection_started"`
	InferenceStarted     bool    `json:"inference_started"`
	SessionGeneration    int64   `json:"session_generation"`
	LastCycleMS          *int64  `json:"last_cycle_ms"`
	LastSuccessfulSendMS *int64  `json:"last_successful_send_ms"`
	QuarantinedSegments  int     `json:"quarantined_segments"`
	SafeErrorCode        *string `json:"safe_error_code"`
	LastFailureCode      *string `json:"last_failure_code"`
}

type collectorConfig struct {
	SchemaVersion        string `json:"schema_version"`
	DeploymentID         string `json:"deployment_id"`
	DeploymentGeneration string `json:"deployment_generation"`
	OwnerSocket          string `json:"owner_socket"`
	TargetConfigured     bool   `json:"target_configured"`
	CollectionEnabled    bool   `json:"collection_enabled"`
	InferenceEnabled     bool   `json:"inference_enabled"`
}

type Runner struct {
	paths          config.Paths
	config         collectorConfig
	pairing        *pairing.LocalState
	transport      collectorTransport
	spool          *spool.Spool
	codec          *store.FrameCodecV1
	reader         darwin.NativeReader
	budget         *ByteBudget
	calls          *NativeCallBudget
	host           *darwin.HostCollector
	process        *darwin.ProcessCollector
	runtime        *collectollama.Collector
	scope          identity.Scope
	expected       []darwin.ExpectedProcess
	bootID         string
	session        protocol.SessionResult
	target         *pairing.LocalTarget
	alignment      Alignment
	sequence       map[string]int64
	statusSequence int64
	sourceHealth   map[string]sourceHealth
	inventoryStale map[string]bool
	pendingStatus  *protocol.SourceStatus
	pendingLossRev uint64
	pendingLosses  int

	mu     sync.Mutex
	status CollectorStatus
}

func NewRunner(paths config.Paths) (*Runner, error) {
	configured, err := readCollectorConfig(paths.CollectorConfig, paths)
	if err != nil {
		return nil, err
	}
	local, err := pairing.Open(paths.Collector, configured.DeploymentID, configured.DeploymentGeneration)
	if err != nil {
		return nil, err
	}
	queue, err := spool.Open(filepath.Join(paths.Collector, "spool"), spool.Options{})
	if err != nil {
		return nil, err
	}
	var transport collectorTransport
	if _, statErr := os.Lstat(paths.RemoteCollectorConfig); statErr == nil {
		if !config.ExperimentalFeaturesEnabled() {
			queue.Close()
			return nil, errors.New(config.ExperimentalMessage)
		}
		transport, err = NewRemoteTransport(paths, configured.DeploymentID, configured.DeploymentGeneration)
	} else if !errors.Is(statErr, os.ErrNotExist) {
		queue.Close()
		return nil, statErr
	} else {
		transport, err = NewLocalTransport(paths.HubSocket)
	}
	if err != nil {
		queue.Close()
		return nil, err
	}
	codec, err := store.NewFrameCodecV1()
	if err != nil {
		transport.Close()
		queue.Close()
		return nil, err
	}
	reader := darwin.NewNativeReader()
	calls := NewNativeCallBudget()
	runner := &Runner{
		paths: paths, config: configured, pairing: local, transport: transport, spool: queue, codec: codec,
		reader: reader, budget: NewByteBudget(), calls: calls, sequence: map[string]int64{}, sourceHealth: map[string]sourceHealth{}, inventoryStale: map[string]bool{},
		status: CollectorStatus{SchemaVersion: domain.SchemaVersion, Service: "collector", State: "starting", TargetState: "none", InferenceStarted: false},
	}
	return runner, nil
}

func Run(ctx context.Context, paths config.Paths) error {
	runner, err := NewRunner(paths)
	if err != nil {
		return err
	}
	defer runner.Close()
	err = runner.Run(ctx)
	if ctx.Err() != nil && errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func (r *Runner) Close() {
	if r.codec != nil {
		r.codec.Close()
		r.codec = nil
	}
	if r.transport != nil {
		r.transport.Close()
	}
	if r.spool != nil {
		_ = r.spool.Close()
	}
}

func (r *Runner) Status(context.Context) (any, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	status := r.status
	if r.spool != nil {
		status.QuarantinedSegments = r.spool.QuarantinedSegments()
	}
	return status, nil
}

func (r *Runner) Run(ctx context.Context) error {
	if err := r.waitForEnable(ctx); err != nil || ctx.Err() != nil {
		return err
	}
	if err := r.bootstrap(ctx); err != nil {
		return err
	}
	if err := r.initializeCollectors(ctx); err != nil {
		return err
	}
	for {
		err := r.runActive(ctx)
		if ctx.Err() != nil {
			r.setStatus("stopped", r.targetState(), r.collectionStarted(), "")
			return nil
		}
		if !errors.Is(err, errCollectionDisabled) {
			return err
		}
		if err := r.waitForEnable(ctx); err != nil || ctx.Err() != nil {
			return err
		}
	}
}

func (r *Runner) runActive(ctx context.Context) error {
	ticker := time.NewTicker(hostInterval)
	defer ticker.Stop()
	now := time.Now()
	nextProcess, nextInventory, nextExchange, nextCredential := now, now, now, now.Add(time.Hour)
	for {
		if now.Compare(nextCredential) >= 0 {
			if maintainer, ok := r.transport.(credentialMaintainer); ok {
				if err := maintainer.MaintainCredential(ctx); err != nil {
					r.setError(err)
					nextCredential = now.Add(5 * time.Minute)
				} else {
					nextCredential = now.Add(time.Hour)
				}
			} else {
				nextCredential = now.Add(time.Hour)
			}
		}
		if err := r.cycle(ctx, now, now.Compare(nextProcess) >= 0, now.Compare(nextInventory) >= 0, now.Compare(nextExchange) >= 0); errors.Is(err, errCollectionDisabled) {
			r.setStatus("configured_paused", r.targetState(), false, "collection_disabled")
			return err
		} else if err != nil {
			r.setError(err)
		} else {
			r.setStatus("running", r.targetState(), true, "")
		}
		if now.Compare(nextProcess) >= 0 {
			nextProcess = now.Add(processInterval)
		}
		if now.Compare(nextInventory) >= 0 {
			nextInventory = now.Add(inventoryInterval)
		}
		if now.Compare(nextExchange) >= 0 {
			nextExchange = now.Add(timeExchangeInterval)
		}
		select {
		case <-ctx.Done():
			return nil
		case now = <-ticker.C:
		}
	}
}

func (r *Runner) waitForEnable(ctx context.Context) error {
	ticker := time.NewTicker(hostInterval)
	defer ticker.Stop()
	for {
		configured, err := readCollectorConfig(r.paths.CollectorConfig, r.paths)
		if err == nil {
			if configured.DeploymentID != r.config.DeploymentID || configured.DeploymentGeneration != r.config.DeploymentGeneration {
				return errors.New("collector configuration identity changed; explicit recovery required")
			}
			r.config = configured
			if configured.CollectionEnabled {
				return nil
			}
			r.setStatus("configured_paused", r.targetState(), false, "collection_disabled")
		} else {
			r.setError(err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (r *Runner) bootstrap(ctx context.Context) error {
	if maintainer, ok := r.transport.(credentialMaintainer); ok {
		if err := r.retry(ctx, maintainer.MaintainCredential); err != nil {
			return err
		}
	}
	state := r.pairing.Snapshot()
	if !state.Registered {
		if err := r.retry(ctx, func(attempt context.Context) error {
			return r.transport.Pair(attempt, state.HostID, state.InstallationID)
		}); err != nil {
			return err
		}
		if err := r.pairing.Registered(); err != nil {
			return err
		}
	}
	if state.PendingActivation != nil {
		r.bootID = state.PendingActivation.CollectorBootID
	} else {
		boot, err := domain.NewUUID()
		if err != nil {
			return err
		}
		r.bootID = boot
	}
	request, err := r.pairing.PrepareActivation(r.bootID)
	if err != nil {
		return err
	}
	var result protocol.SessionResult
	if err := r.retry(ctx, func(attempt context.Context) error {
		var sendErr error
		result, sendErr = r.transport.Activate(attempt, request)
		return sendErr
	}); err != nil {
		return err
	}
	if err := r.pairing.CompleteActivation(result); err != nil {
		return err
	}
	r.session = result
	r.mu.Lock()
	r.status.SessionGeneration = result.SessionGeneration
	r.mu.Unlock()
	return nil
}

func (r *Runner) initializeCollectors(ctx context.Context) error {
	state := r.pairing.Snapshot()
	scope, err := identity.NewScope(state.HostID, r.bootID)
	if err != nil {
		return err
	}
	r.scope = scope
	if own, readErr := r.readProcess(ctx, os.Getpid()); readErr == nil {
		r.expected = []darwin.ExpectedProcess{{PID: own.Identity.PID, ProcessStartIdentity: own.Identity.StartAbsolute, Role: identity.RoleRMTCollector}}
	}
	r.refreshHubIdentity(ctx)
	r.host, err = darwin.NewHostCollector(darwin.HostOptions{HostID: state.HostID, BootID: r.bootID, DataPath: r.paths.Support, Reader: r.reader, CallBudget: r.calls})
	if err != nil {
		return err
	}
	return r.retry(ctx, func(attempt context.Context) error { return r.refreshTarget(attempt, true) })
}

func (r *Runner) readProcess(ctx context.Context, pid int) (darwin.ProcessRead, error) {
	if !r.calls.Acquire(ctx, "process.identity") {
		return darwin.ProcessRead{}, ctx.Err()
	}
	defer r.calls.Release("process.identity")
	return r.reader.Process(ctx, pid)
}

func (r *Runner) cycle(ctx context.Context, now time.Time, processDue, inventoryDue, exchangeDue bool) error {
	configured, err := readCollectorConfig(r.paths.CollectorConfig, r.paths)
	if err != nil {
		return err
	}
	if configured.DeploymentID != r.config.DeploymentID || configured.DeploymentGeneration != r.config.DeploymentGeneration {
		return errors.New("collector configuration identity changed; explicit recovery required")
	}
	if !configured.CollectionEnabled {
		r.config = configured
		return errCollectionDisabled
	}
	r.config = configured
	targetErr := r.refreshTarget(ctx, false)
	var cycleErr error
	if targetErr != nil {
		cycleErr = targetErr
	}
	if exchangeDue {
		sent := time.Now()
		hubMS, timeErr := r.transport.Time(ctx)
		received := time.Now()
		if timeErr == nil {
			r.alignment = TimeExchange(sent, received, hubMS)
		} else if cycleErr == nil {
			cycleErr = timeErr
		}
	}
	if processDue && targetErr == nil {
		r.refreshHubIdentity(ctx)
	}

	var host domain.HostObservation
	var processes *domain.ProcessCollection
	var runtimeSnapshot collectollama.Snapshot
	var group sync.WaitGroup
	group.Add(1)
	go func() { defer group.Done(); host = r.host.Collect(ctx) }()
	if targetErr == nil && processDue && r.process != nil {
		group.Add(1)
		go func() { defer group.Done(); value := r.process.Collect(ctx); processes = &value }()
	}
	if targetErr == nil && r.runtime != nil {
		group.Add(1)
		go func() {
			defer group.Done()
			runtimeSnapshot = r.runtime.Collect(ctx, collectollama.Due{Reachability: true, Inventory: inventoryDue})
		}()
	}
	group.Wait()
	if processes != nil && r.target != nil {
		r.finalizeEndpointAssociation(processes, runtimeSnapshot)
	}

	state := r.pairing.Snapshot()
	r.recordSourceSuccess(state.HostSourceID, now)
	frames := HostFrames(state.HostSourceID, host, processes, r.alignment, now)
	if r.runtime != nil && r.target != nil {
		if runtimeSnapshot.Runtime.Reachable.Value != nil && !r.inventoryStale[r.target.SourceID] {
			r.recordSourceSuccess(r.target.SourceID, now)
		} else {
			reason := domain.MissingCollectionGap
			if runtimeSnapshot.Runtime.Reachable.MissingReason != nil {
				reason = *runtimeSnapshot.Runtime.Reachable.MissingReason
			}
			r.recordSourceFailure(r.target.SourceID, "unavailable", reason, now)
		}
		runtimeFrames := RuntimeFrames(r.target.SourceID, runtimeSnapshot.Runtime, true, inventoryDue, r.alignment, now)
		if inventoryDue {
			models, modelErr := r.inventoryModels(ctx, runtimeSnapshot)
			inventoryErr := modelErr
			if inventoryErr == nil {
				inventoryErr = r.sendInventory(ctx, models, inventoryAssociationState(processes))
			}
			if inventoryErr != nil {
				// A model frame cannot precede the durable model-revision inventory.
				filtered := runtimeFrames[:0]
				for _, frame := range runtimeFrames {
					if frame.Provenance.MethodRevision != "ollama-0.34.0-bounded-ps-v1" {
						filtered = append(filtered, frame)
					}
				}
				runtimeFrames = filtered
				r.inventoryStale[r.target.SourceID] = true
				r.recordSourceFailure(r.target.SourceID, "stale", domain.MissingCollectionGap, now)
				if cycleErr == nil {
					cycleErr = inventoryErr
				}
			} else {
				r.inventoryStale[r.target.SourceID] = false
				r.recordSourceSuccess(r.target.SourceID, now)
			}
		}
		frames = append(frames, runtimeFrames...)
	}
	if err := r.appendFrames(frames); err != nil {
		return err
	}
	if err := r.sendStatus(ctx, now); err != nil {
		return err
	}
	if err := r.sendPending(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	cycleMS := now.UnixMilli()
	r.status.LastCycleMS = &cycleMS
	r.mu.Unlock()
	return cycleErr
}

func readCollectorConfig(path string, paths config.Paths) (collectorConfig, error) {
	var value collectorConfig
	if err := config.ValidatePrivateFile(path); err != nil {
		return value, err
	}
	file, err := os.Open(path)
	if err != nil {
		return value, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil || len(data) > 64<<10 {
		return value, errors.New("collector configuration exceeds limit")
	}
	if err := protocol.DecodeStrictJSON(bytes.NewReader(data), 64<<10, &value); err != nil {
		return value, err
	}
	var raw map[string]json.RawMessage
	_ = json.Unmarshal(data, &raw)
	for _, key := range []string{"schema_version", "deployment_id", "deployment_generation", "owner_socket", "target_configured", "collection_enabled", "inference_enabled"} {
		if _, ok := raw[key]; !ok {
			return value, fmt.Errorf("collector configuration missing %s", key)
		}
	}
	if value.SchemaVersion != domain.SchemaVersion || value.DeploymentID == "" || value.DeploymentGeneration == "" || value.OwnerSocket != paths.CollectorSocket || value.InferenceEnabled {
		return value, errors.New("collector configuration identity or safety boundary is invalid")
	}
	return value, nil
}

func (r *Runner) refreshTarget(ctx context.Context, force bool) error {
	targets, err := pairing.ReadTargets(r.paths.Collector, r.config.DeploymentGeneration)
	if err != nil {
		return err
	}
	var active *pairing.LocalTarget
	for index := range targets.Targets {
		if !targets.Targets[index].Retired {
			copy := targets.Targets[index]
			active = &copy
			break
		}
	}
	unchanged := r.target == nil && active == nil
	if r.target != nil && active != nil {
		unchanged = r.target.TargetID == active.TargetID && r.target.SourceID == active.SourceID && r.target.Revision == active.Revision && r.target.Manifest.ManifestRevision == active.Manifest.ManifestRevision && r.target.ManifestSHA256 == active.ManifestSHA256 && r.target.SelectorSHA256 == active.SelectorSHA256 && r.target.Manifest.IdentityRevision == active.Manifest.IdentityRevision
	}
	if unchanged && !force {
		return nil
	}
	r.runtime, r.process, r.target = nil, nil, nil
	if err := r.sendInventoryFor(ctx, targets, active, nil, "declared_unverified"); err != nil {
		return err
	}
	endpoint := ""
	if active != nil {
		client, err := adapter.NewClient(active.Manifest.Endpoint.URL())
		if err != nil {
			return err
		}
		r.runtime = collectollama.New(client, r.pairing, collectollama.Config{TargetID: active.TargetID})
		endpoint = net.JoinHostPort(active.Manifest.Endpoint.Host, fmt.Sprint(active.Manifest.Endpoint.Port))
		copy := *active
		r.target = &copy
	}
	state := r.pairing.Snapshot()
	process, err := darwin.NewProcessCollector(darwin.ProcessOptions{HostID: state.HostID, BootID: r.bootID, TargetID: targetID(active), Endpoint: endpoint, EndpointHash: endpointHash(active), Scope: r.scope, Expected: r.expected, SampleInterval: processInterval, Reader: r.reader, CallBudget: r.calls})
	if err != nil {
		return err
	}
	r.process = process
	return nil
}

func (r *Runner) refreshHubIdentity(ctx context.Context) {
	pid, start, present, err := r.transport.HubProcessIdentity(ctx)
	if err != nil || !present {
		return
	}
	hub, err := r.readProcess(ctx, pid)
	if err != nil || hub.Identity.StartAbsolute != start {
		return
	}
	expected := make([]darwin.ExpectedProcess, 0, 3)
	for _, process := range r.expected {
		if process.Role == identity.RoleRMTCollector || process.Role == identity.RoleSelectedOllama {
			expected = append(expected, process)
		}
	}
	expected = append(expected, darwin.ExpectedProcess{PID: pid, ProcessStartIdentity: start, Role: identity.RoleRMTHub})
	if expectedProcessesEqual(expected, r.expected) {
		return
	}
	r.expected = expected
	if r.process == nil {
		return
	}
	state := r.pairing.Snapshot()
	endpoint := ""
	if r.target != nil {
		endpoint = net.JoinHostPort(r.target.Manifest.Endpoint.Host, fmt.Sprint(r.target.Manifest.Endpoint.Port))
	}
	process, createErr := darwin.NewProcessCollector(darwin.ProcessOptions{HostID: state.HostID, BootID: r.bootID, TargetID: targetID(r.target), Endpoint: endpoint, EndpointHash: endpointHash(r.target), Scope: r.scope, Expected: r.expected, SampleInterval: processInterval, Reader: r.reader, CallBudget: r.calls})
	if createErr == nil {
		r.process = process
	}
}

func expectedProcessesEqual(left, right []darwin.ExpectedProcess) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func targetID(target *pairing.LocalTarget) string {
	if target == nil {
		return ""
	}
	return target.TargetID
}

func endpointHash(target *pairing.LocalTarget) string {
	if target == nil {
		return ""
	}
	return target.SelectorSHA256
}

func inventoryAssociationState(processes *domain.ProcessCollection) string {
	if processes == nil {
		return "declared_unverified"
	}
	switch processes.Association.Quality {
	case domain.AssociationVerified:
		return "verified"
	case domain.AssociationAmbiguous:
		return "ambiguous"
	default:
		return "declared_unverified"
	}
}

// finalizeEndpointAssociation combines independent listener ownership with a
// successful bounded Ollama version observation and the exact private target
// manifest. Listener ownership alone never confers selected-runtime identity.
func (r *Runner) finalizeEndpointAssociation(processes *domain.ProcessCollection, runtime collectollama.Snapshot) {
	if processes == nil || r.target == nil {
		return
	}
	association := &processes.Association
	association.TargetID = r.target.TargetID
	association.TargetRevision = r.target.Revision
	association.ManifestRevision = r.target.Manifest.ManifestRevision
	association.ManifestSHA256 = r.target.ManifestSHA256
	association.SelectorSHA256 = r.target.SelectorSHA256
	association.IdentityRevision = r.target.Manifest.IdentityRevision
	if runtime.Runtime.Version != nil {
		value := *runtime.Runtime.Version
		association.RuntimeVersion = &value
	}
	if runtime.RuntimeSourcePinID != nil {
		value := *runtime.RuntimeSourcePinID
		association.RuntimeSourcePinID = &value
	}
	if association.Quality == domain.AssociationVerified {
		reachable := runtime.Runtime.Reachable.Value != nil && *runtime.Runtime.Reachable.Value
		manifestBound := association.EndpointHash == r.target.SelectorSHA256 && r.target.Manifest.Validate() == nil && association.RuntimeVersion != nil && association.RuntimeSourcePinID != nil
		if !reachable || !manifestBound {
			reason := domain.MissingIdentityUnverified
			if runtime.Runtime.Reachable.Value != nil && !*runtime.Runtime.Reachable.Value {
				reason = domain.MissingSourceUnreachable
			}
			association.Quality, association.Reason = domain.AssociationDeclaredUnverified, &reason
			association.PID, association.ProcessStartIdentity, association.ProcessKey = nil, nil, nil
		} else {
			matched := false
			for index := range processes.Processes {
				process := &processes.Processes[index]
				if association.PID != nil && association.ProcessStartIdentity != nil && association.ProcessKey != nil && process.PID == *association.PID && process.ProcessStartIdentity == *association.ProcessStartIdentity && process.ProcessKey == *association.ProcessKey {
					process.TargetID = &association.TargetID
					process.AssociationQuality = domain.AssociationVerified
					process.Category = domain.ProcessSelectedOllama
					matched = true
					break
				}
			}
			if !matched {
				reason := domain.MissingPopulationPartial
				association.Quality, association.Reason = domain.AssociationDeclaredUnverified, &reason
				association.PID, association.ProcessStartIdentity, association.ProcessKey = nil, nil, nil
			}
		}
	}
	r.updateSelectedExpected(association, processes.Timing.ObservedWallMS)
}

func (r *Runner) updateSelectedExpected(association *domain.EndpointAssociation, observedMS int64) {
	if association == nil {
		return
	}
	next := make([]darwin.ExpectedProcess, 0, len(r.expected)+1)
	for _, process := range r.expected {
		if process.Role == identity.RoleSelectedOllama {
			exited := association.VerifiedExit != nil && association.VerifiedExit.ProcessKey == process.ProcessKey
			replaced := association.Quality == domain.AssociationVerified && association.ProcessKey != nil && *association.ProcessKey != process.ProcessKey
			if exited || replaced {
				continue
			}
		}
		next = append(next, process)
	}
	if association.Quality == domain.AssociationVerified && association.PID != nil && association.ProcessStartIdentity != nil && association.ProcessKey != nil {
		start, err := strconv.ParseUint(string(*association.ProcessStartIdentity), 10, 64)
		if err == nil {
			updated := darwin.ExpectedProcess{PID: *association.PID, ProcessStartIdentity: start, ProcessKey: *association.ProcessKey, LastSeenMS: observedMS, TargetID: association.TargetID, Role: identity.RoleSelectedOllama}
			found := false
			for index := range next {
				if next[index].Role == identity.RoleSelectedOllama && next[index].ProcessKey == updated.ProcessKey {
					next[index], found = updated, true
					break
				}
			}
			if !found {
				next = append(next, updated)
			}
		}
	}
	r.expected = next
	if r.process != nil {
		r.process.SetExpected(next)
	}
}

func (r *Runner) inventoryModels(ctx context.Context, snapshot collectollama.Snapshot) ([]protocol.InventoryModel, error) {
	if r.target == nil {
		return nil, nil
	}
	loaded := map[string]bool{}
	for _, model := range snapshot.LoadedModels {
		if model.Digest != nil {
			loaded[model.Alias+"\x00"+*model.Digest] = true
		}
	}
	result := make([]protocol.InventoryModel, 0, len(snapshot.AvailableModels))
	seen := map[string]bool{}
	for _, model := range append(snapshot.AvailableModels, snapshot.LoadedModels...) {
		if !model.Local || model.Digest == nil {
			continue
		}
		key := model.Alias + "\x00" + *model.Digest
		if seen[key] {
			continue
		}
		seen[key] = true
		id, err := r.pairing.ResolveModelID(ctx, r.target.TargetID, model.Alias, *model.Digest)
		if err != nil {
			return nil, err
		}
		digest := *model.Digest
		result = append(result, protocol.InventoryModel{ModelID: id, TargetID: r.target.TargetID, Alias: model.Alias, Digest: &digest, ReportedLoaded: loaded[key]})
	}
	if len(result) > 64 {
		return nil, errors.New("model inventory exceeds bound")
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ModelID < result[j].ModelID })
	return result, nil
}

func (r *Runner) sendInventory(ctx context.Context, models []protocol.InventoryModel, associationState string) error {
	targets, err := pairing.ReadTargets(r.paths.Collector, r.config.DeploymentGeneration)
	if err != nil {
		return err
	}
	return r.sendInventoryFor(ctx, targets, r.target, models, associationState)
}

func (r *Runner) sendInventoryFor(ctx context.Context, targets pairing.TargetState, active *pairing.LocalTarget, models []protocol.InventoryModel, associationState string) error {
	if models == nil {
		models = []protocol.InventoryModel{}
	}
	state := r.pairing.Snapshot()
	sources := map[string]protocol.InventorySource{}
	for _, source := range state.InventorySources {
		sources[source.SourceID] = source
	}
	sources[state.HostSourceID] = protocol.InventorySource{SourceID: state.HostSourceID, Kind: "host", CapabilityRevision: domain.RegistryRevision, Active: true}
	configured := map[string]pairing.LocalTarget{}
	for _, target := range targets.Targets {
		configured[target.SourceID] = target
		if previous, ok := sources[target.SourceID]; ok {
			previous.Kind, previous.TargetID, previous.CapabilityRevision, previous.Active = "runtime", stringPointer(target.TargetID), domain.RegistryRevision, !target.Retired
			sources[target.SourceID] = previous
		}
	}
	if active != nil {
		sources[active.SourceID] = protocol.InventorySource{SourceID: active.SourceID, Kind: "runtime", TargetID: stringPointer(active.TargetID), CapabilityRevision: domain.RegistryRevision, Active: true}
	}
	list := make([]protocol.InventorySource, 0, len(sources))
	for id, source := range sources {
		if source.Kind != "host" {
			target, ok := configured[id]
			if !ok {
				return errors.New("remembered inventory source lacks private target identity")
			}
			source.TargetID, source.Active = stringPointer(target.TargetID), !target.Retired
		}
		list = append(list, source)
	}
	if len(list) > 8 {
		return errors.New("remembered inventory sources exceed wire bound")
	}
	sort.Slice(list, func(i, j int) bool { return list[i].SourceID < list[j].SourceID })
	currentTargets := []protocol.InventoryTarget{}
	if active != nil {
		if associationState != "verified" && associationState != "ambiguous" {
			associationState = "declared_unverified"
		}
		currentTargets = append(currentTargets, protocol.InventoryTarget{TargetID: active.TargetID, AdapterID: "ollama", LocalSelectorSHA256: active.SelectorSHA256, AssociationState: associationState})
	}
	payload, _ := json.Marshal(struct {
		Sources []protocol.InventorySource `json:"sources"`
		Targets []protocol.InventoryTarget `json:"targets"`
		Models  []protocol.InventoryModel  `json:"models"`
	}{list, currentTargets, models})
	digest := sha256.Sum256(payload)
	inventory := protocol.CollectorInventory{Protocol: domain.ProtocolVersion, DeploymentID: state.DeploymentID, HostID: state.HostID, SecurityGeneration: state.Generation, SessionGeneration: r.session.SessionGeneration, CollectorBootID: r.bootID, InventoryRevision: hex.EncodeToString(digest[:]), Sources: list, Targets: currentTargets, Models: models}
	if err := inventory.Validate(); err != nil {
		return err
	}
	if err := r.pairing.RememberInventory(inventory); err != nil {
		return err
	}
	result, err := r.transport.Inventory(ctx, inventory)
	if err != nil {
		return err
	}
	return r.pairing.AckInventory(result)
}

func (r *Runner) appendFrames(frames []protocol.CollectorFrame) error {
	state := r.pairing.Snapshot()
	for index := range frames {
		sequence := r.sequence[frames[index].SourceID]
		frames[index].Sequence = sequence
		r.sequence[frames[index].SourceID] = sequence + 1
		payload, _, err := r.codec.Encode(frames[index])
		if err != nil {
			return err
		}
		if err := r.spool.Append(spool.Record{DeploymentID: state.DeploymentID, Generation: state.Generation, SessionGeneration: r.session.SessionGeneration, HostID: state.HostID, BootID: r.bootID, SourceID: frames[index].SourceID, Sequence: uint64(sequence), ObservedMS: frames[index].ObservedWallMS, Payload: payload}); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runner) sendPending(ctx context.Context) error {
	_, err := r.sendLane(ctx, true, 64)
	if err != nil {
		return err
	}
	_, err = r.sendLane(ctx, false, 64)
	return err
}

func (r *Runner) sendLane(ctx context.Context, current bool, maxFrames int) (bool, error) {
	state := r.pairing.Snapshot()
	pending, err := r.spool.ReadPending(r.bootID, state.Generation, current, 256<<10, maxFrames)
	if err != nil || len(pending.Records) == 0 {
		return false, err
	}
	first := pending.Records[0]
	frames := make([]protocol.CollectorFrame, 0, len(pending.Records))
	for _, record := range pending.Records {
		if record.DeploymentID != first.DeploymentID || record.Generation != first.Generation || record.SessionGeneration != first.SessionGeneration || record.HostID != first.HostID || record.BootID != first.BootID {
			_ = r.spool.Quarantine(pending.Cursor, "invalid_frame")
			return true, errors.New("spool batch ownership mismatch")
		}
		frame, decodeErr := r.codec.Decode(record.Payload)
		if decodeErr != nil || frame.SourceID != record.SourceID || frame.Sequence != int64(record.Sequence) || frame.ObservedWallMS != record.ObservedMS {
			_ = r.spool.Quarantine(pending.Cursor, "invalid_frame")
			return true, errors.New("spool frame decode mismatch")
		}
		frames = append(frames, frame)
	}
	batchID, err := domain.NewUUID()
	if err != nil {
		return true, err
	}
	mode := "replay"
	if current {
		mode = "current"
	}
	batch := protocol.CollectorBatch{Protocol: domain.ProtocolVersion, DeliveryMode: mode, SecurityGeneration: first.Generation, SessionGeneration: first.SessionGeneration, DeploymentID: first.DeploymentID, HostID: first.HostID, CollectorBootID: first.BootID, BatchID: batchID, Frames: frames}
	wire, _ := json.Marshal(batch)
	var allowed bool
	if current {
		allowed = r.budget.AllowCurrent(len(wire))
	} else {
		allowed = r.budget.AllowReplay(len(wire))
	}
	if !allowed {
		return true, nil
	}
	ack, err := r.transport.Batch(ctx, batch)
	if err != nil {
		var admission *AdmissionError
		if errors.As(err, &admission) && admission.StatusCode == 413 {
			if len(frames) > 1 {
				return r.sendLane(ctx, current, max(1, maxFrames/2))
			}
			return true, r.spool.Quarantine(pending.Cursor, "oversized_frame")
		}
		if errors.As(err, &admission) && admission.Poison() {
			return true, r.spool.Quarantine(pending.Cursor, "invalid_frame")
		}
		return true, err
	}
	if !ack.Durable {
		return true, errors.New("non-durable batch acknowledgement")
	}
	if err := r.spool.Ack(pending.Cursor); err != nil {
		return true, err
	}
	r.mu.Lock()
	when := time.Now().UnixMilli()
	r.status.LastSuccessfulSendMS = &when
	r.mu.Unlock()
	return true, nil
}

func (r *Runner) sendStatus(ctx context.Context, now time.Time) error {
	if !r.budget.AllowControl(4096) {
		return nil
	}
	if r.pendingStatus != nil {
		err := r.transmitStatus(ctx)
		var admission *AdmissionError
		// The hub accepts an exact lost-ACK duplicate at any age. A 410 for a
		// status older than its 60-second admission window therefore proves the
		// request never committed. Keep its loss ledger unacknowledged, reuse the
		// sequence, and let the next control-lane turn build a fresh observation.
		if err != nil && now.UnixMilli()-r.pendingStatus.ObservedWallMS > 60000 && errors.As(err, &admission) && admission.StatusCode == http.StatusGone {
			r.pendingStatus = nil
			r.pendingLossRev = 0
			r.pendingLosses = 0
		}
		return err
	}
	state := r.pairing.Snapshot()
	sources := make([]protocol.SourceState, 0, len(state.InventorySources))
	for _, source := range state.InventorySources {
		if !source.Active {
			continue
		}
		health, ok := r.sourceHealth[source.SourceID]
		if !ok {
			reason := domain.MissingCollectionGap
			health = sourceHealth{state: "unavailable", failureReason: &reason, failureCount: 1}
		}
		sources = append(sources, protocol.SourceState{SourceID: source.SourceID, State: health.state, LastSuccessMS: health.lastSuccessMS, FailureReason: health.failureReason, FirstFailureMS: health.firstFailureMS, FailureCount: health.failureCount})
	}
	if len(sources) == 0 {
		health := r.sourceHealth[state.HostSourceID]
		sources = append(sources, protocol.SourceState{SourceID: state.HostSourceID, State: health.state, LastSuccessMS: health.lastSuccessMS, FailureReason: health.failureReason, FirstFailureMS: health.firstFailureMS, FailureCount: health.failureCount})
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].SourceID < sources[j].SourceID })
	losses, revision := r.spool.Losses()
	lossIntervals := make([]protocol.LossInterval, 0, min(16, len(losses)))
	for _, loss := range losses {
		if len(lossIntervals) == 16 {
			break
		}
		lossIntervals = append(lossIntervals, protocol.LossInterval{SourceID: loss.SourceID, StartMS: loss.StartMS, EndMS: loss.EndMS, LostCount: int64(loss.Count), Reason: loss.Reason})
	}
	heartbeat := "fresh"
	for _, source := range sources {
		if source.State != "fresh" {
			heartbeat = "degraded"
			break
		}
	}
	r.pendingStatus = &protocol.SourceStatus{Protocol: domain.ProtocolVersion, DeploymentID: state.DeploymentID, HostID: state.HostID, SecurityGeneration: state.Generation, SessionGeneration: r.session.SessionGeneration, CollectorBootID: r.bootID, Sequence: r.statusSequence, ObservedWallMS: now.UnixMilli(), Heartbeat: heartbeat, Sources: sources, LossIntervals: lossIntervals}
	r.pendingLossRev = revision
	r.pendingLosses = len(lossIntervals)
	return r.transmitStatus(ctx)
}

func (r *Runner) transmitStatus(ctx context.Context) error {
	if _, err := r.transport.SourceStatus(ctx, *r.pendingStatus); err != nil {
		return err
	}
	if r.pendingLosses > 0 {
		if err := r.spool.AckLossesPrefix(r.pendingLossRev, r.pendingLosses); err != nil {
			return err
		}
	}
	r.statusSequence++
	r.pendingStatus = nil
	r.pendingLossRev = 0
	r.pendingLosses = 0
	return nil
}

func (r *Runner) recordSourceSuccess(source string, now time.Time) {
	when := now.UnixMilli()
	r.sourceHealth[source] = sourceHealth{state: "fresh", lastSuccessMS: &when}
}

func (r *Runner) recordSourceFailure(source, state string, reason domain.MissingReason, now time.Time) {
	health := r.sourceHealth[source]
	if health.firstFailureMS == nil {
		first := now.UnixMilli()
		health.firstFailureMS = &first
	}
	health.state = state
	health.failureReason = &reason
	health.failureCount++
	if health.failureCount > 1_000_000 {
		health.failureCount = 1_000_000
	}
	r.sourceHealth[source] = health
}

func (r *Runner) retry(ctx context.Context, operation func(context.Context) error) error {
	delay := time.Second
	for {
		err := operation(ctx)
		if err == nil {
			return nil
		}
		var admission *AdmissionError
		if errors.As(err, &admission) && !admission.Retryable() {
			return err
		}
		r.setError(err)
		wait := decorrelated(delay)
		if errors.As(err, &admission) && admission.RetryAfter > wait {
			wait = admission.RetryAfter
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		delay = min(60*time.Second, max(time.Second, wait))
	}
}

func decorrelated(previous time.Duration) time.Duration {
	upper := min(60*time.Second, max(3*time.Second, previous*3))
	span := upper - time.Second
	value, err := rand.Int(rand.Reader, big.NewInt(int64(span)+1))
	if err != nil {
		return min(60*time.Second, previous*2)
	}
	return time.Second + time.Duration(value.Int64())
}

func (r *Runner) targetState() string {
	if r.target == nil {
		return "none"
	}
	return "configured"
}

func (r *Runner) setStatus(state, target string, started bool, safeCode string) {
	r.setStatusWithFailure(state, target, started, safeCode, "")
}

func (r *Runner) setStatusWithFailure(state, target string, started bool, safeCode, failureCode string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status.State, r.status.TargetState, r.status.CollectionStarted = state, target, started
	if safeCode == "" {
		r.status.SafeErrorCode = nil
	} else {
		r.status.SafeErrorCode = stringPointer(safeCode)
	}
	if failureCode == "" {
		r.status.LastFailureCode = nil
	} else {
		r.status.LastFailureCode = stringPointer(failureCode)
	}
}

func (r *Runner) setError(err error) {
	code := "collector_degraded"
	var admission *AdmissionError
	if errors.As(err, &admission) {
		switch {
		case admission.Fenced():
			code = "collector_admission_fenced"
		case admission.Poison():
			code = "collector_payload_quarantined"
		default:
			code = "collector_transport_unavailable"
		}
	}
	if errors.Is(err, spool.ErrCapacity) {
		code = "collector_spool_capacity"
	}
	r.setStatusWithFailure("degraded", r.targetState(), r.collectionStarted(), code, classifyFailure(err))
}

func (r *Runner) collectionStarted() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status.CollectionStarted
}

func stringPointer(value string) *string { return &value }

// classifyFailure intentionally exposes only a bounded diagnostic category.
// Owner status must never carry endpoint URLs, certificate details, file paths,
// request bodies or database errors.
func classifyFailure(err error) string {
	if err == nil {
		return ""
	}
	var phaseErr *transportError
	if errors.As(err, &phaseErr) {
		switch phaseErr.phase {
		case transportPhaseTLS:
			return "transport_tls"
		case transportPhaseWrite:
			return "transport_network_write"
		case transportPhaseRead:
			return "transport_network_read"
		default:
			return "transport_network_dial"
		}
	}
	var admission *AdmissionError
	if errors.As(err, &admission) {
		return fmt.Sprintf("admission_http_%d", admission.StatusCode)
	}
	root := err
	var requestErr *url.Error
	if errors.As(root, &requestErr) && requestErr.Err != nil {
		root = requestErr.Err
	}
	if errors.Is(root, context.DeadlineExceeded) {
		return "transport_timeout"
	}
	// TLS handshake failures are commonly wrapped in net.OpError, which also
	// satisfies net.Error. Classify the protocol layer before the broad network
	// category so an alert does not hide a certificate or handshake failure.
	message := strings.ToLower(root.Error())
	if strings.Contains(message, "tls") || strings.Contains(message, "certificate") || strings.Contains(message, "x509") {
		return "transport_tls"
	}
	var networkErr net.Error
	if errors.As(root, &networkErr) {
		if networkErr.Timeout() {
			return "transport_timeout"
		}
		return "transport_network"
	}
	if strings.Contains(message, "json") || strings.Contains(message, "acknowledgement") || strings.Contains(message, "response") {
		return "response_invalid"
	}
	return "collector_error"
}
