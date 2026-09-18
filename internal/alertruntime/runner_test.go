package alertruntime

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) set(now time.Time) {
	c.mu.Lock()
	c.now = now
	c.mu.Unlock()
}

type fakeTicker struct{ values chan time.Time }

func (t *fakeTicker) C() <-chan time.Time { return t.values }
func (t *fakeTicker) Stop()               {}

type evaluatorFunc func(context.Context, Cycle) error

func (f evaluatorFunc) EvaluateCurrent(ctx context.Context, cycle Cycle) error { return f(ctx, cycle) }

func TestRunnerUsesMonotonicContinuityAndResetsAfterFailureOrLateTick(t *testing.T) {
	origin := time.Now()
	clock := &fakeClock{now: origin}
	ticks := &fakeTicker{values: make(chan time.Time, 8)}
	var cycles []Cycle
	completed := make(chan struct{}, 8)
	failSecond := true
	runner := New(evaluatorFunc(func(_ context.Context, cycle Cycle) error {
		cycles = append(cycles, cycle)
		completed <- struct{}{}
		if len(cycles) == 2 && failSecond {
			return errors.New("bounded fixture failure")
		}
		return nil
	}), nil)
	runner.clock = clock
	runner.newTicker = func(time.Duration) ticker { return ticks }

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); runner.Run(ctx) }()

	step := func(at time.Duration, scheduled time.Duration) {
		clock.set(origin.Add(at))
		ticks.values <- origin.Add(scheduled)
		select {
		case <-completed:
		case <-time.After(time.Second):
			t.Fatal("evaluation did not complete")
		}
	}
	step(5*time.Second, 5*time.Second)
	step(10*time.Second, 10*time.Second)
	step(15*time.Second, 15*time.Second)
	failSecond = false
	step(20*time.Second, 15*time.Second) // scheduler lag exceeds the pass budget

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runner did not join after cancellation")
	}
	if len(cycles) != 4 {
		t.Fatalf("cycles = %#v", cycles)
	}
	if !cycles[0].Restarted || cycles[0].Elapsed != 0 {
		t.Fatalf("first cycle = %#v", cycles[0])
	}
	if cycles[1].Restarted || cycles[1].Elapsed != Cadence {
		t.Fatalf("continuous cycle = %#v", cycles[1])
	}
	if !cycles[2].Restarted || cycles[2].Elapsed != 0 {
		t.Fatalf("post-failure cycle = %#v", cycles[2])
	}
	if !cycles[3].Restarted || cycles[3].Elapsed != 0 || cycles[3].Lag != 5*time.Second {
		t.Fatalf("late cycle = %#v", cycles[3])
	}
	status := runner.Status()
	if !status.Started || status.LastAttemptMS == nil || status.LastSuccessMS == nil || status.LastPassFailed || status.LagMS != 0 {
		t.Fatalf("status = %#v", status)
	}
}

func TestRunnerNeverOverlapsPassesAndReportsBoundedFailure(t *testing.T) {
	origin := time.Now()
	clock := &fakeClock{now: origin.Add(Cadence)}
	ticks := &fakeTicker{values: make(chan time.Time, 2)}
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	errorsSeen := make(chan error, 1)
	active := 0
	maxActive := 0
	runner := New(evaluatorFunc(func(ctx context.Context, _ Cycle) error {
		active++
		if active > maxActive {
			maxActive = active
		}
		entered <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
		}
		active--
		return errors.New("fixture failure")
	}), func(err error) { errorsSeen <- err })
	runner.clock = clock
	runner.newTicker = func(time.Duration) ticker { return ticks }

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); runner.Run(ctx) }()
	ticks.values <- origin.Add(Cadence)
	<-entered
	ticks.values <- origin.Add(2 * Cadence)
	select {
	case <-entered:
		t.Fatal("second pass overlapped the first")
	case <-time.After(10 * time.Millisecond):
	}
	close(release)
	select {
	case <-errorsSeen:
	case <-time.After(time.Second):
		t.Fatal("failure was not reported")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runner did not stop")
	}
	if maxActive != 1 {
		t.Fatalf("max active = %d", maxActive)
	}
	status := runner.Status()
	if !status.Started || status.LastAttemptMS == nil || status.LastSuccessMS != nil || !status.LastPassFailed {
		t.Fatalf("failed status = %#v", status)
	}
}

func TestStatusLagUsesLastCompletedSuccessOrStart(t *testing.T) {
	origin := time.Now()
	clock := &fakeClock{now: origin}
	runner := New(evaluatorFunc(func(context.Context, Cycle) error { return nil }), nil)
	runner.clock = clock
	if status := runner.Status(); status.Started || status.LagMS != 0 {
		t.Fatalf("unstarted status = %#v", status)
	}
	runner.mu.Lock()
	runner.startedAt = origin
	runner.status.Started = true
	runner.mu.Unlock()
	clock.set(origin.Add(16 * time.Second))
	if status := runner.Status(); status.LagMS != 16_000 {
		t.Fatalf("pre-success lag = %#v", status)
	}
	runner.mu.Lock()
	runner.lastOKAt = origin.Add(10 * time.Second)
	successMS := runner.lastOKAt.UnixMilli()
	runner.status.LastSuccessMS = &successMS
	runner.mu.Unlock()
	if status := runner.Status(); status.LagMS != 6_000 {
		t.Fatalf("post-success lag = %#v", status)
	}
}
