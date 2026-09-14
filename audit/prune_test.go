package audit

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPostgresPrune(t *testing.T) {
	pool := freshDB(t)
	log := NewPostgres(pool)
	ctx := context.Background()
	now := time.Now().UTC()
	for i := 0; i < 7; i++ {
		if err := log.Record(ctx, Event{OccurredAt: now.Add(-48 * time.Hour), Action: "old"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Record(ctx, Event{OccurredAt: now, Action: "fresh"}); err != nil {
		t.Fatal(err)
	}
	n, err := log.Prune(ctx, 24*time.Hour, 3)
	if err != nil || n != 7 {
		t.Fatalf("Prune = %d, %v; want 7", n, err)
	}
	left, _ := log.List(ctx, "", 0)
	if len(left) != 1 || left[0].Action != "fresh" {
		t.Fatalf("left = %+v", left)
	}
	if n, err := log.Prune(ctx, 24*time.Hour, 0); err != nil || n != 0 {
		t.Fatalf("default batch Prune = %d, %v", n, err)
	}
	if _, err := log.Prune(ctx, 0, 10); err == nil {
		t.Fatal("olderThan <= 0 must be rejected (would wipe the log)")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := log.Prune(cancelled, time.Hour, 10); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Prune = %v", err)
	}
	pool.Close()
	if _, err := log.Prune(ctx, time.Hour, 10); err == nil {
		t.Fatal("Prune on closed pool: want error")
	}
}
