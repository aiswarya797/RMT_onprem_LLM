package scheduler

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"testing"
	"time"

	"rmt.local/monitor/internal/collector/pairing"
	"rmt.local/monitor/internal/collector/spool"
	"rmt.local/monitor/internal/protocol"
	"rmt.local/monitor/internal/store"
)

type fakeTransport struct {
	activations []protocol.SessionActivation
	batches     []protocol.CollectorBatch
	statuses    []protocol.SourceStatus
	statusErr   error
}

func (f *fakeTransport) Pair(context.Context, string, string) error { return nil }
func (f *fakeTransport) Activate(_ context.Context, request protocol.SessionActivation) (protocol.SessionResult, error) {
	f.activations = append(f.activations, request)
	return protocol.NewSessionResult(request, request.ExpectedPreviousGeneration+1, time.Now().UnixMilli()), nil
}
func (f *fakeTransport) Inventory(_ context.Context, request protocol.CollectorInventory) (protocol.InventoryResult, error) {
	return protocol.InventoryResult{InventoryRevision: request.InventoryRevision, Durable: true, Current: true}, nil
}
func (f *fakeTransport) Batch(_ context.Context, request protocol.CollectorBatch) (protocol.BatchACK, error) {
	f.batches = append(f.batches, request)
	return protocol.BatchACK{BatchID: request.BatchID, Durable: true, Accepted: len(request.Frames), ControlRequests: []protocol.ControlRequest{}}, nil
}
func (f *fakeTransport) SourceStatus(_ context.Context, request protocol.SourceStatus) (protocol.StatusACK, error) {
	f.statuses = append(f.statuses, request)
	if f.statusErr != nil {
		return protocol.StatusACK{}, f.statusErr
	}
	return protocol.StatusACK{CollectorBootID: request.CollectorBootID, Sequence: request.Sequence, Durable: true, ControlRequests: []protocol.ControlRequest{}}, nil
}
func (f *fakeTransport) Time(context.Context) (int64, error) { return 0, nil }
func (f *fakeTransport) HubProcessIdentity(context.Context) (int, uint64, bool, error) {
	return 0, 0, false, nil
}
func (f *fakeTransport) Close() {}

func TestBootstrapRetriesPendingActivationWithOriginalBoot(t *testing.T) {
	local, err := pairing.Create(t.TempDir(), testUUID(1), testUUID(2))
	if err != nil {
		t.Fatal(err)
	}
	if err := local.Registered(); err != nil {
		t.Fatal(err)
	}
	pending, err := local.PrepareActivation(testUUID(3))
	if err != nil {
		t.Fatal(err)
	}
	transport := &fakeTransport{}
	runner := &Runner{pairing: local, transport: transport, status: CollectorStatus{}}
	if err := runner.bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runner.bootID != pending.CollectorBootID || len(transport.activations) != 1 || transport.activations[0] != pending {
		t.Fatalf("pending activation was replaced: boot=%s requests=%+v", runner.bootID, transport.activations)
	}
	state := local.Snapshot()
	if state.PendingActivation != nil || state.PreviousSession != 1 {
		t.Fatalf("activation was not durably completed: %+v", state)
	}
}

func TestClassifyFailureExposesOnlyBoundedTransportCategories(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "timeout", err: context.DeadlineExceeded, want: "transport_timeout"},
		{name: "network", err: &url.Error{Op: "Post", URL: "https://192.168.1.2:9444/collector/v1/sessions", Err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}}, want: "transport_network"},
		{name: "tls", err: &url.Error{Op: "Post", URL: "https://192.168.1.2:9444/collector/v1/sessions", Err: errors.New("tls: failed to verify certificate")}, want: "transport_tls"},
		{name: "tls wrapped as network", err: &url.Error{Op: "Post", URL: "https://192.168.1.2:9444/collector/v1/sessions", Err: &net.OpError{Op: "remote error", Net: "tcp", Err: errors.New("remote error: tls: bad certificate")}}, want: "transport_tls"},
		{name: "dial phase", err: &transportError{phase: transportPhaseDial, err: errors.New("connection refused")}, want: "transport_network_dial"},
		{name: "write phase", err: &transportError{phase: transportPhaseWrite, err: errors.New("write failed")}, want: "transport_network_write"},
		{name: "read phase", err: &transportError{phase: transportPhaseRead, err: errors.New("read failed")}, want: "transport_network_read"},
		{name: "response", err: errors.New("activation acknowledgement is invalid"), want: "response_invalid"},
		{name: "admission", err: &AdmissionError{StatusCode: http.StatusConflict}, want: "admission_http_409"},
		{name: "fallback", err: errors.New("unexpected collector failure"), want: "collector_error"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyFailure(test.err); got != test.want {
				t.Fatalf("classifyFailure()=%q, want %q", got, test.want)
			}
		})
	}
}

func TestSourceStatusRetriesExactRequestAfterLostACK(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	local, err := pairing.Create(t.TempDir(), testUUID(1), testUUID(2))
	if err != nil {
		t.Fatal(err)
	}
	queue, err := spool.Open(t.TempDir(), spool.Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	transport := &fakeTransport{statusErr: errors.New("lost acknowledgement")}
	runner := &Runner{
		pairing: local, transport: transport, spool: queue, budget: newByteBudget(func() time.Time { return now }),
		bootID: testUUID(3), session: protocol.SessionResult{SessionGeneration: 1}, sourceHealth: map[string]sourceHealth{},
	}
	runner.recordSourceSuccess(local.Snapshot().HostSourceID, now)
	if err := runner.sendStatus(context.Background(), now); err == nil {
		t.Fatal("lost acknowledgement was accepted")
	}
	first := transport.statuses[0]
	now = now.Add(5 * time.Second)
	transport.statusErr = nil
	if err := runner.sendStatus(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if len(transport.statuses) != 2 || !reflect.DeepEqual(first, transport.statuses[1]) {
		t.Fatalf("status retry changed request: first=%+v second=%+v", first, transport.statuses[1])
	}
	if runner.pendingStatus != nil || runner.statusSequence != 1 {
		t.Fatalf("status retry state not advanced exactly once: pending=%+v sequence=%d", runner.pendingStatus, runner.statusSequence)
	}
}

func TestSourceStatusReplacesUncommittedStaleRequestAfterDefinitiveRejection(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	local, err := pairing.Create(t.TempDir(), testUUID(1), testUUID(2))
	if err != nil {
		t.Fatal(err)
	}
	queue, err := spool.Open(t.TempDir(), spool.Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	transport := &fakeTransport{statusErr: &AdmissionError{StatusCode: http.StatusGone}}
	runner := &Runner{
		pairing: local, transport: transport, spool: queue, budget: newByteBudget(func() time.Time { return now }),
		bootID: testUUID(3), session: protocol.SessionResult{SessionGeneration: 1}, sourceHealth: map[string]sourceHealth{},
	}
	runner.recordSourceSuccess(local.Snapshot().HostSourceID, now)
	stale := protocol.SourceStatus{Protocol: "1.0", DeploymentID: local.Snapshot().DeploymentID, HostID: local.Snapshot().HostID, SecurityGeneration: local.Snapshot().Generation, SessionGeneration: 1, CollectorBootID: testUUID(3), Sequence: 0, ObservedWallMS: now.Add(-61 * time.Second).UnixMilli(), Heartbeat: "fresh", Sources: []protocol.SourceState{{SourceID: local.Snapshot().HostSourceID, State: "fresh", FailureCount: 0}}, LossIntervals: []protocol.LossInterval{}}
	runner.pendingStatus = &stale
	if err := runner.sendStatus(context.Background(), now); err == nil {
		t.Fatal("stale uncommitted status rejection was hidden")
	}
	if runner.pendingStatus != nil || runner.statusSequence != 0 {
		t.Fatalf("stale request was not replaced safely: pending=%+v sequence=%d", runner.pendingStatus, runner.statusSequence)
	}
	now = now.Add(5 * time.Second)
	transport.statusErr = nil
	if err := runner.sendStatus(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if len(transport.statuses) != 2 || transport.statuses[1].Sequence != stale.Sequence || transport.statuses[1].ObservedWallMS != now.UnixMilli() || runner.statusSequence != 1 {
		t.Fatalf("fresh replacement did not preserve sequence exactly once: statuses=%+v next=%d", transport.statuses, runner.statusSequence)
	}
}

func TestSendPendingAdvancesCurrentBeforeReplay(t *testing.T) {
	now := time.Now()
	local, err := pairing.Create(t.TempDir(), testUUID(1), testUUID(2))
	if err != nil {
		t.Fatal(err)
	}
	queue, err := spool.Open(t.TempDir(), spool.Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	codec, err := store.NewFrameCodecV1()
	if err != nil {
		t.Fatal(err)
	}
	defer codec.Close()
	fixture, err := os.ReadFile("../../../fixtures/contracts/valid/collector-batch.json")
	if err != nil {
		t.Fatal(err)
	}
	batch, err := protocol.DecodeCollectorBatch(bytes.NewReader(fixture))
	if err != nil {
		t.Fatal(err)
	}
	frame := batch.Frames[0]
	for index, item := range []struct {
		boot string
		at   time.Time
	}{{testUUID(4), now.Add(-time.Minute)}, {testUUID(3), now}} {
		frame.Sequence = int64(index)
		frame.ObservedWallMS = item.at.UnixMilli()
		payload, _, err := codec.Encode(frame)
		if err != nil {
			t.Fatal(err)
		}
		if err := queue.Append(spool.Record{DeploymentID: local.Snapshot().DeploymentID, Generation: local.Snapshot().Generation, SessionGeneration: 1, HostID: local.Snapshot().HostID, BootID: item.boot, SourceID: frame.SourceID, Sequence: uint64(index), ObservedMS: item.at.UnixMilli(), Payload: payload}); err != nil {
			t.Fatal(err)
		}
	}
	transport := &fakeTransport{}
	runner := &Runner{pairing: local, transport: transport, spool: queue, codec: codec, budget: NewByteBudget(), bootID: testUUID(3)}
	if err := runner.sendPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(transport.batches) != 2 || transport.batches[0].DeliveryMode != "current" || transport.batches[1].DeliveryMode != "replay" {
		t.Fatalf("send order = %+v", transport.batches)
	}
}

func TestNativeBudgetReservesRuntimeAndTransportLanes(t *testing.T) {
	budget := NewNativeCallBudget()
	if !budget.Acquire(context.Background(), "one") || !budget.Acquire(context.Background(), "two") {
		t.Fatal("two native slots were not available")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if budget.Acquire(ctx, "three") {
		t.Fatal("third native call exceeded four-lane partition")
	}
	budget.Release("one")
	budget.Release("two")
}

func testUUID(suffix byte) string {
	return "00000000-0000-4000-8000-00000000000" + string('0'+suffix)
}
