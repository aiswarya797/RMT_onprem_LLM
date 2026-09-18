// Package alertruntime schedules the hub's deterministic current-state alert
// pass. Input construction, evaluation and persistence remain behind the
// injected evaluator so this loop never duplicates metric semantics.
package alertruntime

import (
	"context"
	"sync"
	"time"
)

const (
	Cadence     = 5 * time.Second
	PassTimeout = 2 * time.Second
)

// Cycle is the bounded time envelope for one current-state evaluation pass.
// Elapsed is derived from the process monotonic clock. Restarted is set after
// startup, an unsuccessful pass or a scheduling gap so unobserved time cannot
// advance pending or recovery dwell.
type Cycle struct {
	EventTime time.Time
	Elapsed   time.Duration
	Lag       time.Duration
	Restarted bool
}

type Status struct {
	Started        bool   `json:"started"`
	LastAttemptMS  *int64 `json:"last_attempt_ms"`
	LastSuccessMS  *int64 `json:"last_success_ms"`
	LagMS          int64  `json:"lag_ms"`
	LastPassFailed bool   `json:"last_pass_failed"`
}

type Evaluator interface {
	EvaluateCurrent(context.Context, Cycle) error
}

type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

type ticker interface {
	C() <-chan time.Time
	Stop()
}

type realTicker struct{ *time.Ticker }

func (t realTicker) C() <-chan time.Time { return t.Ticker.C }

type Runner struct {
	evaluator Evaluator
	clock     Clock
	newTicker func(time.Duration) ticker
	onError   func(error)
	mu        sync.Mutex
	status    Status
	startedAt time.Time
	lastOKAt  time.Time
}

func New(evaluator Evaluator, onError func(error)) *Runner {
	return &Runner{
		evaluator: evaluator,
		clock:     realClock{},
		newTicker: func(interval time.Duration) ticker { return realTicker{time.NewTicker(interval)} },
		onError:   onError,
	}
}

// Status returns the evaluator's bounded health without exposing pass errors
// or evidence. Lag is elapsed monotonic time since the last completed success,
// or since the runner started if no pass has completed successfully.
func (r *Runner) Status() Status {
	if r == nil {
		return Status{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	result := r.status
	if !result.Started {
		return result
	}
	boundary := r.lastOKAt
	if boundary.IsZero() {
		boundary = r.startedAt
	}
	lag := r.clock.Now().Sub(boundary)
	if lag < 0 {
		lag = 0
	}
	result.LagMS = lag.Milliseconds()
	return result
}

// Run evaluates sequentially until ctx is cancelled. A ticker may coalesce
// delayed ticks, but this loop never overlaps passes or creates per-tick
// goroutines.
func (r *Runner) Run(ctx context.Context) {
	if r == nil || r.evaluator == nil {
		return
	}
	r.mu.Lock()
	r.startedAt = r.clock.Now()
	r.status.Started = true
	r.mu.Unlock()
	ticks := r.newTicker(Cadence)
	defer ticks.Stop()

	var lastSuccessfulStart time.Time
	continuity := false
	for {
		select {
		case <-ctx.Done():
			return
		case scheduled := <-ticks.C():
			started := r.clock.Now()
			tickerLag := started.Sub(scheduled)
			if tickerLag < 0 {
				tickerLag = 0
			}
			r.mu.Lock()
			lagBoundary := r.lastOKAt
			if lagBoundary.IsZero() {
				lagBoundary = r.startedAt
			}
			lastSuccessLag := started.Sub(lagBoundary)
			if lastSuccessLag < 0 {
				lastSuccessLag = 0
			}
			lag := max(tickerLag, lastSuccessLag)
			attemptMS := started.UnixMilli()
			r.status.LastAttemptMS = &attemptMS
			r.mu.Unlock()
			restarted := !continuity || lastSuccessfulStart.IsZero()
			elapsed := time.Duration(0)
			if !restarted {
				elapsed = started.Sub(lastSuccessfulStart)
				if elapsed < 0 || elapsed > Cadence+PassTimeout || tickerLag > PassTimeout {
					restarted = true
					elapsed = 0
				}
			}

			passCtx, cancel := context.WithTimeout(ctx, PassTimeout)
			err := r.evaluator.EvaluateCurrent(passCtx, Cycle{EventTime: started, Elapsed: elapsed, Lag: lag, Restarted: restarted})
			cancel()
			if err != nil {
				continuity = false
				r.mu.Lock()
				r.status.LastPassFailed = true
				r.mu.Unlock()
				if r.onError != nil && ctx.Err() == nil {
					r.onError(err)
				}
				continue
			}
			lastSuccessfulStart = started
			continuity = true
			completed := r.clock.Now()
			successMS := completed.UnixMilli()
			r.mu.Lock()
			r.lastOKAt = completed
			r.status.LastSuccessMS = &successMS
			r.status.LastPassFailed = false
			r.mu.Unlock()
		}
	}
}
