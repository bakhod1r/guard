// Package audit records security events (logins, role changes, policy edits).
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bakhod1r/guard/kernel/pgerr"
)

type Event struct {
	ID         string         `json:"id"`
	OccurredAt time.Time      `json:"occurred_at"`
	ActorID    string         `json:"actor_id,omitempty"`
	Action     string         `json:"action"`
	Target     string         `json:"target,omitempty"`
	Success    bool           `json:"success"`
	IP         string         `json:"ip,omitempty"`
	UserAgent  string         `json:"user_agent,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

type Log interface {
	Record(ctx context.Context, e Event) error
	List(ctx context.Context, actorID string, limit int) ([]Event, error)
}

func prepare(e *Event) {
	if e.ID == "" {
		e.ID = uuid.Must(uuid.NewV7()).String()
	}
	if e.OccurredAt.IsZero() {
		e.OccurredAt = time.Now().UTC()
	}
	if e.Metadata == nil {
		e.Metadata = map[string]any{}
	}
}

type Postgres struct{ db *pgxpool.Pool }

func NewPostgres(db *pgxpool.Pool) *Postgres { return &Postgres{db: db} }

func (p *Postgres) Record(ctx context.Context, e Event) error {
	prepare(&e)
	var actor any
	if e.ActorID != "" {
		actor = e.ActorID
	}
	err := p.insert(ctx, e, actor)
	if actor != nil && pgerr.IsInvalidText(err) {
		// The actor id does not fit the host id type (e.g. "abc" for bigint). Keep the
		// event: store actor_id NULL and preserve the raw value in metadata.
		meta := make(map[string]any, len(e.Metadata)+1)
		for k, v := range e.Metadata {
			meta[k] = v
		}
		meta["actor_id"] = e.ActorID
		e.Metadata = meta
		err = p.insert(ctx, e, nil)
	}
	return err
}

func (p *Postgres) insert(ctx context.Context, e Event, actor any) error {
	meta, err := json.Marshal(e.Metadata)
	if err != nil {
		return err
	}
	_, err = p.db.Exec(ctx, insertEvent,
		e.ID, e.OccurredAt, actor, e.Action, e.Target, e.Success, e.IP, truncate(e.UserAgent, 512), meta)
	return err
}

const insertEvent = `INSERT INTO guard_audit_event (id, occurred_at, actor_id, action, target, success, ip, user_agent, metadata)
	VALUES ($1,$2,$3,$4,NULLIF($5,''),$6,NULLIF($7,''),NULLIF($8,''),$9)
	ON CONFLICT (id) DO NOTHING`

// RecordBatch inserts events in one round trip; idempotent by Event.ID, so
// retried batches are safe. An actor id not fitting the host id type fails the
// whole batch, which then falls back to per-event Record.
func (p *Postgres) RecordBatch(ctx context.Context, events []Event) error {
	if len(events) == 0 {
		return nil
	}
	prepared := make([]Event, len(events))
	b := &pgx.Batch{}
	for i, e := range events {
		prepare(&e)
		prepared[i] = e
		meta, err := json.Marshal(e.Metadata)
		if err != nil {
			return err
		}
		var actor any
		if e.ActorID != "" {
			actor = e.ActorID
		}
		b.Queue(insertEvent, e.ID, e.OccurredAt, actor, e.Action, e.Target, e.Success, e.IP, truncate(e.UserAgent, 512), meta)
	}
	// pgx sends a multi-statement batch as an implicit transaction: all or nothing.
	err := p.db.SendBatch(ctx, b).Close()
	if pgerr.IsInvalidText(err) {
		for _, e := range prepared {
			if err := p.Record(ctx, e); err != nil {
				return err
			}
		}
		return nil
	}
	return err
}

func (p *Postgres) List(ctx context.Context, actorID string, limit int) ([]Event, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT id::text, occurred_at, COALESCE(actor_id::text,''), action, COALESCE(target,''), success,
		COALESCE(ip,''), COALESCE(user_agent,''), metadata FROM guard_audit_event`
	args := []any{limit}
	if actorID != "" {
		q += ` WHERE actor_id = $2`
		args = append(args, actorID)
	}
	rows, err := p.db.Query(ctx, q+` ORDER BY occurred_at DESC LIMIT $1`, args...)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Event, error) {
		var e Event
		var meta []byte
		err := r.Scan(&e.ID, &e.OccurredAt, &e.ActorID, &e.Action, &e.Target, &e.Success, &e.IP, &e.UserAgent, &meta)
		_ = json.Unmarshal(meta, &e.Metadata)
		return e, err
	})
	// pgx reports a malformed actor id (22P02) lazily, from rows.Err, not from Query.
	if pgerr.IsInvalidText(err) {
		return []Event{}, nil
	}
	return out, err
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Memory keeps events in process; for tests.
type Memory struct {
	mu     sync.Mutex
	Events []Event
}

func (m *Memory) Record(_ context.Context, e Event) error {
	prepare(&e)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Events = append(m.Events, e)
	return nil
}

func (m *Memory) List(_ context.Context, actorID string, limit int) ([]Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Event{}
	for i := len(m.Events) - 1; i >= 0 && (limit <= 0 || len(out) < limit); i-- {
		if actorID == "" || m.Events[i].ActorID == actorID {
			out = append(out, m.Events[i])
		}
	}
	return out, nil
}

// DefaultPruneBatch is used by Prune when batch <= 0.
const DefaultPruneBatch = 1000

// Prune deletes events older than olderThan in batches of batch rows, so a
// large backlog never holds one long transaction or lock. Returns rows deleted.
func (p *Postgres) Prune(ctx context.Context, olderThan time.Duration, batch int) (int64, error) {
	if olderThan <= 0 {
		return 0, errors.New("audit: Prune olderThan must be positive")
	}
	if batch <= 0 {
		batch = DefaultPruneBatch
	}
	cutoff := time.Now().UTC().Add(-olderThan)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		tag, err := p.db.Exec(ctx, `DELETE FROM guard_audit_event WHERE id IN (
			SELECT id FROM guard_audit_event WHERE occurred_at < $1 ORDER BY occurred_at LIMIT $2)`, cutoff, batch)
		if err != nil {
			return total, err
		}
		total += tag.RowsAffected()
		if tag.RowsAffected() < int64(batch) {
			return total, nil
		}
	}
}
