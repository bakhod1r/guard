package audit

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// asyncWriteTimeout bounds one background write so a stuck database cannot
// make Close wait forever beyond the caller's context.
const asyncWriteTimeout = 5 * time.Second

// Async decouples request latency from audit storage. Record never blocks:
// when the buffer is full the event is dropped, counted and logged. Close
// flushes what is buffered; events recorded after Close are written
// synchronously so shutdown paths do not lose them.
type Async struct {
	next    Log
	logger  *slog.Logger
	ch      chan Event
	done    chan struct{}
	dropped atomic.Int64

	mu     sync.RWMutex
	closed bool
}

// NewAsync wraps next. buffer < 1 is treated as 1; logger nil uses slog.Default().
func NewAsync(next Log, buffer int, logger *slog.Logger) *Async {
	if buffer < 1 {
		buffer = 1
	}
	if logger == nil {
		logger = slog.Default()
	}
	a := &Async{next: next, logger: logger, ch: make(chan Event, buffer), done: make(chan struct{})}
	go a.run()
	return a
}

func (a *Async) run() {
	defer close(a.done)
	for e := range a.ch {
		ctx, cancel := context.WithTimeout(context.Background(), asyncWriteTimeout)
		if err := a.next.Record(ctx, e); err != nil {
			a.logger.Warn("guard: audit write failed", "action", e.Action, "event_id", e.ID, "error", err.Error())
		}
		cancel()
	}
}

func (a *Async) Record(ctx context.Context, e Event) error {
	prepare(&e) // stamp id and time at the moment of the event, not of the write
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		return a.next.Record(ctx, e)
	}
	select {
	case a.ch <- e:
	default:
		if n := a.dropped.Add(1); n == 1 || n%1000 == 0 {
			a.logger.Warn("guard: audit buffer full, events dropped", "dropped", n, "action", e.Action)
		}
	}
	return nil
}

func (a *Async) List(ctx context.Context, actorID string, limit int) ([]Event, error) {
	return a.next.List(ctx, actorID, limit)
}

// Dropped reports how many events were discarded because the buffer was full.
func (a *Async) Dropped() int64 { return a.dropped.Load() }

// Close stops accepting buffered events and waits for the flush or ctx.
// It is safe to call more than once. It never closes next.
func (a *Async) Close(ctx context.Context) error {
	a.mu.Lock()
	if !a.closed {
		a.closed = true
		close(a.ch)
	}
	a.mu.Unlock()
	select {
	case <-a.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
