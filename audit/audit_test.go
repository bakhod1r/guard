package audit

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestPostgresRecordAndList(t *testing.T) {
	pool := freshDB(t)
	log := NewPostgres(pool)
	ctx := context.Background()
	actor, other := newUser(t, pool), newUser(t, pool)
	t0 := time.Now().UTC().Truncate(time.Microsecond)

	events := []Event{
		{OccurredAt: t0, ActorID: actor, Action: "login", Target: "user:1", Success: true, IP: "1.2.3.4",
			UserAgent: strings.Repeat("a", 600), Metadata: map[string]any{"k": "v"}},
		{OccurredAt: t0.Add(time.Second), ActorID: other, Action: "logout"},
		{OccurredAt: t0.Add(2 * time.Second), Action: "system"},
	}
	for _, e := range events {
		if err := log.Record(ctx, e); err != nil {
			t.Fatal(err)
		}
	}

	cases := []struct {
		name    string
		actor   string
		limit   int
		actions []string
	}{
		{"all newest first, zero limit defaults", "", 0, []string{"system", "logout", "login"}},
		{"limit applies", "", 2, []string{"system", "logout"}},
		{"limit above max defaults", "", 501, []string{"system", "logout", "login"}},
		{"negative limit defaults", "", -1, []string{"system", "logout", "login"}},
		{"filter by actor", actor, 10, []string{"login"}},
		{"invalid actor text", "abc", 10, []string{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := log.List(ctx, c.actor, c.limit)
			if err != nil {
				t.Fatal(err)
			}
			if got == nil || len(got) != len(c.actions) {
				t.Fatalf("got %+v", got)
			}
			for i, a := range c.actions {
				if got[i].Action != a {
					t.Fatalf("pos %d: want %s got %s", i, a, got[i].Action)
				}
			}
		})
	}

	got, _ := log.List(ctx, actor, 1)
	e := got[0]
	if e.ID == "" || !e.OccurredAt.Equal(t0) || e.Target != "user:1" || !e.Success || e.IP != "1.2.3.4" ||
		len(e.UserAgent) != 512 || e.Metadata["k"] != "v" {
		t.Fatalf("round trip: %+v", e)
	}
}

func TestPostgresRecordInvalidActorKeepsEventWithMetadata(t *testing.T) {
	pool := freshDB(t)
	log := NewPostgres(pool)
	ctx := context.Background()
	if err := log.Record(ctx, Event{ActorID: "abc", Action: "login", Metadata: map[string]any{"x": 1.0}}); err != nil {
		t.Fatal(err)
	}
	got, err := log.List(ctx, "", 10)
	if err != nil || len(got) != 1 {
		t.Fatalf("list: %+v %v", got, err)
	}
	if got[0].ActorID != "" || got[0].Metadata["actor_id"] != "abc" || got[0].Metadata["x"] != 1.0 {
		t.Fatalf("event: %+v", got[0])
	}
}

func TestPostgresRecordUnmarshalableMetadata(t *testing.T) {
	pool := freshDB(t)
	err := NewPostgres(pool).Record(context.Background(), Event{Action: "x", Metadata: map[string]any{"c": make(chan int)}})
	if err == nil {
		t.Fatal("want json error")
	}
}

func TestPostgresStorageErrorsPropagate(t *testing.T) {
	pool := freshDB(t)
	log := NewPostgres(pool)
	pool.Close()
	ctx := context.Background()
	if err := log.Record(ctx, Event{Action: "x", ActorID: "1"}); err == nil {
		t.Error("Record: want error")
	}
	if _, err := log.List(ctx, "", 10); err == nil {
		t.Error("List: want error")
	}
}

func TestPostgresListOutOfRangeActorIsError(t *testing.T) {
	pool := freshDB(t)
	if _, err := NewPostgres(pool).List(context.Background(), "99999999999999999999", 10); err == nil {
		t.Fatal("want numeric out of range error")
	}
}

func TestMemoryRecordAndList(t *testing.T) {
	m := &Memory{}
	ctx := context.Background()
	for _, e := range []Event{{ActorID: "a", Action: "1"}, {ActorID: "b", Action: "2"}, {ActorID: "a", Action: "3"}} {
		if err := m.Record(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if m.Events[0].ID == "" || m.Events[0].OccurredAt.IsZero() || m.Events[0].Metadata == nil {
		t.Fatalf("prepare defaults: %+v", m.Events[0])
	}
	cases := []struct {
		actor string
		limit int
		want  []string
	}{
		{"", 0, []string{"3", "2", "1"}},
		{"", 2, []string{"3", "2"}},
		{"a", 0, []string{"3", "1"}},
		{"a", 1, []string{"3"}},
		{"zzz", 0, []string{}},
	}
	for _, c := range cases {
		got, err := m.List(ctx, c.actor, c.limit)
		if err != nil || got == nil || len(got) != len(c.want) {
			t.Fatalf("%+v: %+v %v", c, got, err)
		}
		for i, a := range c.want {
			if got[i].Action != a {
				t.Fatalf("%+v pos %d: got %s", c, i, got[i].Action)
			}
		}
	}
}

func TestPrepareKeepsProvidedValues(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e := Event{ID: "id", OccurredAt: at, Metadata: map[string]any{"k": 1}}
	prepare(&e)
	if e.ID != "id" || !e.OccurredAt.Equal(at) || e.Metadata["k"] != 1 {
		t.Fatalf("%+v", e)
	}
}
