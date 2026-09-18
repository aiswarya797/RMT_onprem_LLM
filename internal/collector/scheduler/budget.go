package scheduler

import (
	"context"
	"sync"
	"time"
)

const (
	totalBytesPerSecond  = 256 << 10
	replayBytesPerSecond = 128 << 10
	totalBurstBytes      = 256 << 10
	currentReserveBytes  = 64 << 10
)

type ByteBudget struct {
	mu                 sync.Mutex
	now                func() time.Time
	updated            time.Time
	total, replay      float64
	lastControlAttempt time.Time
}

func NewByteBudget() *ByteBudget { return newByteBudget(time.Now) }

func newByteBudget(now func() time.Time) *ByteBudget {
	instant := now()
	return &ByteBudget{now: now, updated: instant, total: totalBurstBytes, replay: replayBytesPerSecond}
}

func (b *ByteBudget) AllowCurrent(size int) bool {
	return b.allow(size, false)
}

func (b *ByteBudget) AllowReplay(size int) bool {
	return b.allow(size, true)
}

func (b *ByteBudget) AllowControl(size int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if size < 0 || size > protocolControlBytes || (!b.lastControlAttempt.IsZero() && now.Sub(b.lastControlAttempt) < 5*time.Second) {
		return false
	}
	b.lastControlAttempt = now
	return true
}

func (b *ByteBudget) allow(size int, replay bool) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if size < 0 || size > totalBurstBytes {
		return false
	}
	now := b.now()
	elapsed := now.Sub(b.updated)
	if elapsed < 0 {
		elapsed = 0
	}
	b.updated = now
	b.total = min(float64(totalBurstBytes), b.total+elapsed.Seconds()*totalBytesPerSecond)
	b.replay = min(float64(replayBytesPerSecond), b.replay+elapsed.Seconds()*replayBytesPerSecond)
	bytes := float64(size)
	if bytes > b.total {
		return false
	}
	if replay && (bytes > b.replay || b.total-bytes < currentReserveBytes) {
		return false
	}
	b.total -= bytes
	if replay {
		b.replay -= bytes
	}
	return true
}

const protocolControlBytes = 4 << 10

// NativeCallBudget gives Darwin two slots. The single runtime call and the
// single owner-socket transport lane complete the fixed four-call partition.
type NativeCallBudget struct{ slots chan struct{} }

func NewNativeCallBudget() *NativeCallBudget {
	return &NativeCallBudget{slots: make(chan struct{}, 2)}
}

func (b *NativeCallBudget) Acquire(ctx context.Context, _ string) bool {
	select {
	case b.slots <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (b *NativeCallBudget) Release(string) { <-b.slots }
