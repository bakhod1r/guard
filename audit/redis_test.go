package audit

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newBuffer(t *testing.T, next Log, cfg RedisBufferConfig) (*RedisBuffer, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return NewRedisBuffer(rdb, next, cfg), mr
}

func TestRedisBufferQueuesThenFlushesInBatches(t *testing.T) {
	ctx := context.Background()
	mem := &batchMemory{}
	b, mr := newBuffer(t, mem, RedisBufferConfig{Prefix: "t:", BatchSize: 3, Interval: time.Hour})
	for i := 0; i < 7; i++ {
		if err := b.Record(ctx, Event{Action: "login"}); err != nil {
			t.Fatal(err)
		}
	}
	if n, _ := mr.List("t:{audit}:queue"); len(n) != 7 {
		t.Fatalf("queued %d", len(n))
	}
	if len(mem.Events) != 0 {
		t.Fatal("must not write before flush")
	}
	n, err := b.Flush(ctx)
	if err != nil || n != 7 {
		t.Fatalf("flush = %d, %v", n, err)
	}
	if len(mem.Events) != 7 || mem.batches != 3 {
		t.Fatalf("events %d batches %d", len(mem.Events), mem.batches)
	}
	if mem.Events[0].ID == "" || mem.Events[0].OccurredAt.IsZero() {
		t.Fatalf("not prepared: %+v", mem.Events[0])
	}
	if mr.Exists("t:{audit}:queue") {
		t.Fatal("queue not drained")
	}
	if mr.Exists("t:{audit}:lock") {
		t.Fatal("lock not released")
	}
}

func TestRedisBufferFlushesOnIntervalAndClose(t *testing.T) {
	ctx := context.Background()
	mem := &batchMemory{}
	b, _ := newBuffer(t, mem, RedisBufferConfig{Interval: 10 * time.Millisecond})
	_ = b.Record(ctx, Event{Action: "a"})
	deadline := time.Now().Add(2 * time.Second)
	for mem.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if mem.count() != 1 {
		t.Fatal("interval flush did not run")
	}
	_ = b.Record(ctx, Event{Action: "b"})
	if err := b.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(ctx); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if mem.count() != 2 {
		t.Fatalf("close did not flush: %d", mem.count())
	}
	// After Close events go straight to next.
	_ = b.Record(ctx, Event{Action: "late"})
	if mem.count() != 3 {
		t.Fatal("late event lost")
	}
}

func TestRedisBufferFallsBackWhenRedisDown(t *testing.T) {
	ctx := context.Background()
	mem := &Memory{}
	b, mr := newBuffer(t, mem, RedisBufferConfig{Interval: time.Hour})
	mr.Close()
	if err := b.Record(ctx, Event{Action: "login"}); err != nil {
		t.Fatal(err)
	}
	if len(mem.Events) != 1 {
		t.Fatal("event lost when redis down")
	}
	if _, err := b.Flush(ctx); err == nil {
		t.Fatal("flush must report redis error")
	}
}

func TestRedisBufferFailedBatchStaysQueued(t *testing.T) {
	ctx := context.Background()
	mem := &batchMemory{fail: errors.New("db down")}
	b, mr := newBuffer(t, mem, RedisBufferConfig{Interval: time.Hour})
	_ = b.Record(ctx, Event{Action: "a"})
	if _, err := b.Flush(ctx); err == nil {
		t.Fatal("want error")
	}
	if l, _ := mr.List("guard:{audit}:queue"); len(l) != 1 {
		t.Fatalf("event must stay queued, got %d", len(l))
	}
	mem.fail = nil
	if n, err := b.Flush(ctx); err != nil || n != 1 {
		t.Fatalf("retry flush = %d %v", n, err)
	}
}

func TestRedisBufferSkipsWhenAnotherFlusherHoldsLock(t *testing.T) {
	ctx := context.Background()
	mem := &batchMemory{}
	b, mr := newBuffer(t, mem, RedisBufferConfig{Interval: time.Hour})
	_ = b.Record(ctx, Event{Action: "a"})
	_ = mr.Set("guard:{audit}:lock", "other")
	if n, err := b.Flush(ctx); err != nil || n != 0 {
		t.Fatalf("flush = %d %v", n, err)
	}
	if mem.count() != 0 {
		t.Fatal("wrote without lock")
	}
}

func TestRedisBufferPlainLogAndPoisonEvent(t *testing.T) {
	ctx := context.Background()
	mem := &Memory{}
	b, mr := newBuffer(t, mem, RedisBufferConfig{Interval: time.Hour})
	_ = b.Record(ctx, Event{Action: "ok"})
	mr.RPush("guard:{audit}:queue", "{not json")
	n, err := b.Flush(ctx)
	if err != nil || n != 2 {
		t.Fatalf("flush = %d %v", n, err)
	}
	if len(mem.Events) != 1 {
		t.Fatalf("events %d", len(mem.Events))
	}
	if l, _ := mr.List("guard:{audit}:dead"); len(l) != 1 {
		t.Fatalf("poison event must go to dead list, got %d", len(l))
	}
	got, _ := b.List(ctx, "", 0)
	if len(got) != 1 {
		t.Fatal("List must delegate")
	}
}

// batchMemory is a Memory that also implements BatchRecorder.
type batchMemory struct {
	Memory
	mu2     sync.Mutex
	batches int
	fail    error
	onBatch func()
}

func (m *batchMemory) Record(ctx context.Context, e Event) error {
	if m.fail != nil {
		return m.fail
	}
	return m.Memory.Record(ctx, e)
}

func (m *batchMemory) RecordBatch(ctx context.Context, events []Event) error {
	m.mu2.Lock()
	defer m.mu2.Unlock()
	if m.fail != nil {
		return m.fail
	}
	if m.onBatch != nil {
		m.onBatch()
	}
	m.batches++
	for _, e := range events {
		_ = m.Memory.Record(ctx, e)
	}
	return nil
}

func (m *batchMemory) count() int {
	m.Memory.mu.Lock()
	defer m.Memory.mu.Unlock()
	return len(m.Events)
}

// rejectLog fails Record for events whose Action is "bad".
type rejectLog struct{ Memory }

func (r *rejectLog) Record(ctx context.Context, e Event) error {
	if e.Action == "bad" {
		return errors.New("rejected")
	}
	return r.Memory.Record(ctx, e)
}

func TestRedisBufferRejectedEventDoesNotBlockQueue(t *testing.T) {
	ctx := context.Background()
	next := &rejectLog{}
	b, mr := newBuffer(t, next, RedisBufferConfig{Interval: time.Hour})
	_ = b.Record(ctx, Event{Action: "ok"})
	_ = b.Record(ctx, Event{Action: "bad"})
	if n, err := b.Flush(ctx); err != nil || n != 2 {
		t.Fatalf("flush = %d %v", n, err)
	}
	if len(next.Events) != 1 || mr.Exists("guard:{audit}:queue") {
		t.Fatal("good event not written or queue not drained")
	}
	if l, _ := mr.List("guard:{audit}:dead"); len(l) != 1 {
		t.Fatalf("dead = %d", len(l))
	}
}

func TestRedisBufferOnlyUndecodableEntries(t *testing.T) {
	ctx := context.Background()
	b, mr := newBuffer(t, &Memory{}, RedisBufferConfig{Interval: time.Hour})
	mr.RPush("guard:{audit}:queue", "x")
	if n, err := b.Flush(ctx); err != nil || n != 1 || mr.Exists("guard:{audit}:queue") {
		t.Fatalf("flush = %d %v", n, err)
	}
}

func TestRedisBufferLockLostDuringWrite(t *testing.T) {
	ctx := context.Background()
	mem := &batchMemory{}
	b, mr := newBuffer(t, mem, RedisBufferConfig{Interval: time.Hour})
	mem.onBatch = func() { _ = mr.Set("guard:{audit}:lock", "other") }
	_ = b.Record(ctx, Event{Action: "a"})
	if _, err := b.Flush(ctx); err == nil {
		t.Fatal("want lock-expired error")
	}
	if l, _ := mr.List("guard:{audit}:queue"); len(l) != 1 {
		t.Fatal("queue must stay untouched")
	}
}

func TestRedisBufferConcurrentFlushersWriteOnce(t *testing.T) {
	ctx := context.Background()
	mem := &batchMemory{}
	mr := miniredis.RunT(t)
	var bufs []*RedisBuffer
	for i := 0; i < 2; i++ {
		rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		t.Cleanup(func() { _ = rdb.Close() })
		bufs = append(bufs, NewRedisBuffer(rdb, mem, RedisBufferConfig{BatchSize: 7, Interval: time.Millisecond}))
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(b *RedisBuffer) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = b.Record(ctx, Event{Action: "x"})
			}
		}(bufs[i%2])
	}
	wg.Wait()
	for _, b := range bufs {
		if err := b.Close(ctx); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]bool{}
	for _, e := range mem.Events {
		if seen[e.ID] {
			t.Fatalf("duplicate %s", e.ID)
		}
		seen[e.ID] = true
	}
	if len(seen) != 200 || mr.Exists("guard:{audit}:queue") {
		t.Fatalf("written %d", len(seen))
	}
}

func TestRedisBufferCloseTimeoutThenRetry(t *testing.T) {
	mem := &batchMemory{}
	b, _ := newBuffer(t, mem, RedisBufferConfig{})
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_ = b.Record(context.Background(), Event{Action: "a"})
	_ = b.Close(cancelled) // may or may not beat the flusher exit
	if err := b.Close(context.Background()); err != nil || mem.count() != 1 {
		t.Fatalf("retry close = %v, written %d", err, mem.count())
	}
}

func TestRedisBufferRunLogsFlushError(t *testing.T) {
	var buf safeBuffer
	mem := &batchMemory{fail: errors.New("db down")}
	b, _ := newBuffer(t, mem, RedisBufferConfig{Interval: 5 * time.Millisecond, Logger: slog.New(slog.NewTextHandler(&buf, nil))})
	_ = b.Record(context.Background(), Event{Action: "a"})
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(buf.String(), "audit flush failed") && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !strings.Contains(buf.String(), "audit flush failed") {
		t.Fatal("flush error not logged")
	}
	c, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_ = b.Close(c)
}

type safeBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestRedisBufferTrimFailsAfterWrite(t *testing.T) {
	ctx := context.Background()
	mem := &batchMemory{}
	b, mr := newBuffer(t, mem, RedisBufferConfig{Interval: time.Hour})
	_ = b.Record(ctx, Event{Action: "a"})
	mem.onBatch = func() { mr.SetError("boom") }
	defer mr.SetError("")
	if _, err := b.Flush(ctx); err == nil {
		t.Fatal("want trim error")
	}
}
