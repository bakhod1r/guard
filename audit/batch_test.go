package audit

import (
	"context"
	"strings"
	"testing"
)

func countEvents(t *testing.T, p *Postgres) int {
	t.Helper()
	var n int
	if err := p.db.QueryRow(context.Background(), `SELECT count(*) FROM guard_audit_event`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPostgresRecordBatchEmpty(t *testing.T) {
	if err := (&Postgres{}).RecordBatch(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresRecordBatchInsertsIdempotent(t *testing.T) {
	pool := freshDB(t)
	p := NewPostgres(pool)
	ctx := context.Background()
	uid := newUser(t, pool)
	events := make([]Event, 5)
	for i := range events {
		events[i] = Event{ID: newID(), ActorID: uid, Action: "login", Success: true, UserAgent: strings.Repeat("a", 600)}
	}
	events = append(events, Event{Action: "anon"}) // prepared id, no actor
	if err := p.RecordBatch(ctx, events); err != nil {
		t.Fatal(err)
	}
	if n := countEvents(t, p); n != 6 {
		t.Fatalf("count = %d, want 6", n)
	}
	// Retry of the same batch (fixed ids) must not duplicate.
	if err := p.RecordBatch(ctx, events[:5]); err != nil {
		t.Fatal(err)
	}
	if err := p.Record(ctx, events[0]); err != nil {
		t.Fatal(err)
	}
	if n := countEvents(t, p); n != 6 {
		t.Fatalf("count after retry = %d, want 6", n)
	}
	got, err := p.List(ctx, uid, 10)
	if err != nil || len(got) != 5 || len(got[0].UserAgent) != 512 {
		t.Fatalf("list = %d events, err %v", len(got), err)
	}
}

func TestPostgresRecordBatchInvalidActorFallsBack(t *testing.T) {
	pool := freshDB(t)
	p := NewPostgres(pool)
	ctx := context.Background()
	uid := newUser(t, pool)
	events := []Event{
		{ID: newID(), ActorID: uid, Action: "ok"},
		{ID: newID(), ActorID: "abc", Action: "bad"},
	}
	if err := p.RecordBatch(ctx, events); err != nil {
		t.Fatal(err)
	}
	if n := countEvents(t, p); n != 2 {
		t.Fatalf("count = %d, want 2", n)
	}
	all, err := p.List(ctx, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range all {
		if e.Action == "bad" && (e.ActorID != "" || e.Metadata["actor_id"] != "abc") {
			t.Fatalf("bad event = %+v", e)
		}
	}
}

func newID() string { e := Event{}; prepare(&e); return e.ID }

func TestPostgresRecordBatchUnmarshalableMetadata(t *testing.T) {
	err := (&Postgres{}).RecordBatch(context.Background(), []Event{{Action: "x", Metadata: map[string]any{"c": make(chan int)}}})
	if err == nil {
		t.Fatal("want json error")
	}
}

func TestPostgresRecordBatchFallbackErrorPropagates(t *testing.T) {
	pool := freshDB(t)
	p := NewPostgres(pool)
	events := []Event{
		{ID: newID(), ActorID: "abc", Action: "bad actor"}, // fails batch with invalid text
		{ID: newID(), Action: "too long ip", IP: strings.Repeat("9", 100)},
	}
	if err := p.RecordBatch(context.Background(), events); err == nil {
		t.Fatal("want fallback Record error")
	}
}
