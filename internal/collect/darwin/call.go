package darwin

import (
	"context"
	"sync"
	"time"
)

// CallBudget is supplied by the scheduler so Darwin reads and runtime HTTP
// calls share the four-call ceiling while retaining a runtime lane. Acquire
// must return when ctx ends. Component names are stable (`host.*`,
// `process.scan`) so the scheduler can reserve lanes without importing this
// package.
type CallBudget interface {
	Acquire(context.Context, string) bool
	Release(string)
}

type localCallBudget struct{ slots chan struct{} }

func newLocalCallBudget(limit int) CallBudget {
	return &localCallBudget{slots: make(chan struct{}, limit)}
}

func (budget *localCallBudget) Acquire(ctx context.Context, _ string) bool {
	select {
	case budget.slots <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (budget *localCallBudget) Release(string) { <-budget.slots }

type callResult[T any] struct {
	value T
	err   error
}

// boundedCall permits at most one underlying native call per component. A
// timed-out uninterruptible syscall is not replaced by another goroutine on
// later ticks; its eventual result is discarded before a fresh read starts.
type boundedCall[T any] struct {
	mu       sync.Mutex
	inFlight bool
}

func (call *boundedCall[T]) invoke(ctx context.Context, timeout time.Duration, budget CallBudget, component string, read func(context.Context) (T, error)) (T, error) {
	var zero T
	call.mu.Lock()
	if call.inFlight {
		call.mu.Unlock()
		return zero, context.DeadlineExceeded
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	if !budget.Acquire(callCtx, component) {
		call.mu.Unlock()
		cancel()
		return zero, context.DeadlineExceeded
	}
	done := make(chan callResult[T], 1)
	call.inFlight = true
	call.mu.Unlock()
	go func() {
		value, err := read(callCtx)
		budget.Release(component)
		call.mu.Lock()
		call.inFlight = false
		call.mu.Unlock()
		done <- callResult[T]{value: value, err: err}
	}()
	select {
	case result := <-done:
		cancel()
		return result.value, result.err
	case <-callCtx.Done():
		cancel()
		return zero, callCtx.Err()
	}
}
