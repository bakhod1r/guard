// Package audit records security events (logins, role changes, policy edits).
package audit

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
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
	meta, err := json.Marshal(e.Metadata)
	if err != nil {
		return err
	}
	var actor any
	if _, err := uuid.Parse(e.ActorID); err == nil {
		actor = e.ActorID
	}
	_, err = p.db.Exec(ctx, `INSERT INTO guard_audit_event (id, occurred_at, actor_id, action, target, success, ip, user_agent, metadata)
		VALUES ($1,$2,$3,$4,NULLIF($5,''),$6,NULLIF($7,''),NULLIF($8,''),$9)`,
		e.ID, e.OccurredAt, actor, e.Action, e.Target, e.Success, e.IP, truncate(e.UserAgent, 512), meta)
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
		if _, err := uuid.Parse(actorID); err != nil {
			return []Event{}, nil
		}
		q += ` WHERE actor_id = $2`
		args = append(args, actorID)
	}
	rows, err := p.db.Query(ctx, q+` ORDER BY occurred_at DESC LIMIT $1`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		var meta []byte
		if err := rows.Scan(&e.ID, &e.OccurredAt, &e.ActorID, &e.Action, &e.Target, &e.Success, &e.IP, &e.UserAgent, &meta); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(meta, &e.Metadata)
		out = append(out, e)
	}
	return out, rows.Err()
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
