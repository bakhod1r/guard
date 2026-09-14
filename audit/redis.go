package audit

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// BatchRecorder is implemented by logs that can store many events in one round
// trip. Writes must be idempotent by Event.ID: a batch may be retried.
type BatchRecorder interface {
	RecordBatch(ctx context.Context, events []Event) error
}

// RedisBufferConfig tunes RedisBuffer. Zero values use the defaults below.
type RedisBufferConfig struct {
	// Prefix namespaces keys. Default "guard:".
	Prefix string
	// BatchSize is the maximum events per database write. Default 500.
	BatchSize int
	// Interval between background flushes. Default 1s.
	Interval time.Duration
	// Logger receives flush failures. Default slog.Default().
	Logger *slog.Logger
}

const (
	defaultBufferBatch    = 500
	defaultBufferInterval = time.Second
	bufferLockTTL         = 30 * time.Second
)

// RedisBuffer queues events in a Redis list and writes them to next in
// batches. The queue survives process restarts and is shared by every
// instance; a Redis lock lets one flusher drain it at a time. When Redis is
// unavailable Record writes to next synchronously, so events are not lost.
// List reads next only: queued events appear after the next flush.
type RedisBuffer struct {
	rdb    redis.UniversalClient
	next   Log
	cfg    RedisBufferConfig
	queue  string
	dead   string
	lock   string
	stop   chan struct{}
	done   chan struct{}
	mu     sync.RWMutex
	closed bool
}

// NewRedisBuffer starts the background flusher. Call Close to stop it.
func NewRedisBuffer(rdb redis.UniversalClient, next Log, cfg RedisBufferConfig) *RedisBuffer {
	if cfg.Prefix == "" {
		cfg.Prefix = "guard:"
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = defaultBufferBatch
	}
	if cfg.Interval <= 0 {
		cfg.Interval = defaultBufferInterval
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	b := &RedisBuffer{
		rdb: rdb, next: next, cfg: cfg,
		// The hash tag keeps all keys in one Redis Cluster slot for the Lua scripts.
		queue: cfg.Prefix + "{audit}:queue", dead: cfg.Prefix + "{audit}:dead", lock: cfg.Prefix + "{audit}:lock",
		stop: make(chan struct{}), done: make(chan struct{}),
	}
	go b.run()
	return b
}

func (b *RedisBuffer) run() {
	defer close(b.done)
	t := time.NewTicker(b.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-b.stop:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), bufferLockTTL)
			if _, err := b.Flush(ctx); err != nil {
				b.cfg.Logger.Warn("guard: audit flush failed", "error", err.Error())
			}
			cancel()
		}
	}
}

func (b *RedisBuffer) Record(ctx context.Context, e Event) error {
	prepare(&e)
	// Hold the read lock across the push so Close's final flush sees it.
	b.mu.RLock()
	defer b.mu.RUnlock()
	if !b.closed {
		raw, err := json.Marshal(e)
		if err == nil {
			if err = b.rdb.RPush(ctx, b.queue, raw).Err(); err == nil {
				return nil
			}
		}
		b.cfg.Logger.Warn("guard: audit queue unavailable, writing directly", "action", e.Action, "error", err.Error())
	}
	return b.next.Record(ctx, e)
}

func (b *RedisBuffer) List(ctx context.Context, actorID string, limit int) ([]Event, error) {
	return b.next.List(ctx, actorID, limit)
}

// KEYS: queue, lock, dead; ARGV: token, count, ttl_ms, dead entries...
var trimIfLocked = redis.NewScript(`
if redis.call('GET', KEYS[2]) ~= ARGV[1] then return 0 end
redis.call('LTRIM', KEYS[1], ARGV[2], -1)
redis.call('PEXPIRE', KEYS[2], ARGV[3])
for i = 4, #ARGV do redis.call('RPUSH', KEYS[3], ARGV[i]) end
return 1`)

// KEYS: lock; ARGV: token
var unlock = redis.NewScript(`
if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) end
return 0`)

// Flush drains the queue into next and returns how many queued entries were
// consumed. It returns 0, nil when another instance holds the flush lock. A
// failed write leaves its batch queued for the next attempt; entries that are
// not valid events, or that next rejects while others in the batch succeed,
// move to the "{audit}:dead" list. One call stops after half the lock TTL so
// the lock never expires mid-drain; the next tick continues.
func (b *RedisBuffer) Flush(ctx context.Context) (int, error) {
	token := uuid.NewString()
	ok, err := b.rdb.SetNX(ctx, b.lock, token, bufferLockTTL).Result()
	if err != nil || !ok {
		return 0, err
	}
	defer func() {
		c, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		unlock.Run(c, b.rdb, []string{b.lock}, token)
	}()
	start := time.Now()
	total := 0
	for {
		raws, err := b.rdb.LRange(ctx, b.queue, 0, int64(b.cfg.BatchSize-1)).Result()
		if err != nil || len(raws) == 0 {
			return total, err
		}
		events := make([]Event, 0, len(raws))
		var dead []any
		for _, raw := range raws {
			var e Event
			if json.Unmarshal([]byte(raw), &e) != nil {
				dead = append(dead, raw)
				continue
			}
			events = append(events, e)
		}
		rejected, err := b.write(ctx, events)
		if err != nil {
			return total, err
		}
		dead = append(dead, rejected...)
		args := append([]any{token, len(raws), bufferLockTTL.Milliseconds()}, dead...)
		kept, err := trimIfLocked.Run(ctx, b.rdb, []string{b.queue, b.lock, b.dead}, args...).Int()
		if err != nil {
			return total, err
		}
		if kept == 0 {
			return total, errors.New("audit: flush lock expired during write")
		}
		total += len(raws)
		if len(raws) < b.cfg.BatchSize || time.Since(start) > bufferLockTTL/2 {
			return total, nil
		}
	}
}

// write stores events. When the batch fails it retries one by one: if every
// event fails the error is treated as transient and returned; otherwise the
// failing events are returned as rejected (encoded) so one bad row cannot
// block the queue.
func (b *RedisBuffer) write(ctx context.Context, events []Event) ([]any, error) {
	if len(events) == 0 {
		return nil, nil
	}
	if br, ok := b.next.(BatchRecorder); ok {
		if br.RecordBatch(ctx, events) == nil {
			return nil, nil
		}
	}
	var rejected []any
	var firstErr error
	for _, e := range events {
		if err := b.next.Record(ctx, e); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			raw, _ := json.Marshal(e)
			rejected = append(rejected, string(raw))
		}
	}
	if len(rejected) == len(events) {
		return nil, firstErr
	}
	if len(rejected) > 0 {
		b.cfg.Logger.Warn("guard: audit events rejected, moved to dead list", "count", len(rejected), "error", firstErr.Error())
	}
	return rejected, nil
}

// Close stops the background flusher and drains the queue once more within
// ctx. Later events are written to next directly. Calling it again retries
// the drain. It never closes next.
func (b *RedisBuffer) Close(ctx context.Context) error {
	b.mu.Lock()
	if !b.closed {
		b.closed = true
		close(b.stop)
	}
	b.mu.Unlock()
	select {
	case <-b.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	_, err := b.Flush(ctx)
	return err
}
