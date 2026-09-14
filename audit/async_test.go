package audit

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// blockingLog blocks Record until release is closed, then fails when err is set.
type blockingLog struct {
	Memory
	release chan struct{}
	err     error
}

func (b *blockingLog) Record(ctx context.Context, e Event) error {
	<-b.release
	if b.err != nil {
		return b.err
	}
	return b.Memory.Record(ctx, e)
}

func TestAsyncFlushesOnClose(t *testing.T) {
	ctx := context.Background()
	mem := &Memory{}
	a := NewAsync(mem, 16, nil)
	for i := 0; i < 10; i++ {
		if err := a.Record(ctx, Event{Action: "login"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(ctx); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	got, _ := a.List(ctx, "", 0)
	if len(got) != 10 || got[0].ID == "" || got[0].OccurredAt.IsZero() {
		t.Fatalf("flushed %d events: %+v", len(got), got)
	}
	if a.Dropped() != 0 {
		t.Fatalf("dropped = %d", a.Dropped())
	}
	// After Close, events are written synchronously instead of being lost.
	if err := a.Record(ctx, Event{Action: "late"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := mem.List(ctx, "", 0); len(got) != 11 {
		t.Fatalf("late record lost: %d", len(got))
	}
}

func TestAsyncDropsWhenFullAndNeverBlocks(t *testing.T) {
	ctx := context.Background()
	var buf bytes.Buffer
	next := &blockingLog{release: make(chan struct{})}
	a := NewAsync(next, 1, slog.New(slog.NewTextHandler(&buf, nil)))
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			_ = a.Record(ctx, Event{Action: "flood"})
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Record blocked on a full buffer")
	}
	if a.Dropped() < 48 {
		t.Fatalf("dropped = %d, want >= 48", a.Dropped())
	}
	// Flush cannot finish while the writer is stuck: Close honours ctx.
	c, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if err := a.Close(c); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close = %v", err)
	}
	close(next.release)
	if err := a.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "dropped") {
		t.Fatalf("drop not logged: %q", buf.String())
	}
}

func TestAsyncLogsWriteFailures(t *testing.T) {
	var buf syncBuffer
	next := &blockingLog{release: make(chan struct{}), err: errors.New("disk full")}
	close(next.release)
	a := NewAsync(next, 0, slog.New(slog.NewTextHandler(&buf, nil)))
	_ = a.Record(context.Background(), Event{Action: "x"})
	if err := a.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := buf.String(); !strings.Contains(s, "level=WARN") || !strings.Contains(s, "disk full") {
		t.Fatalf("log = %q", s)
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
