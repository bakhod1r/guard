// Package infrastructure stores API keys in PostgreSQL (or memory for tests).
package infrastructure

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bakhod1r/guard/apikey/domain"
	"github.com/bakhod1r/guard/kernel/pgerr"
)

type Postgres struct{ db *pgxpool.Pool }

func NewPostgres(db *pgxpool.Pool) *Postgres { return &Postgres{db: db} }

const keyColumns = `id::text, user_id::text, name, prefix, hash, scopes, expires_at, revoked_at, last_used_at, created_at`

func scanKey(row pgx.Row) (*domain.Key, error) {
	var k domain.Key
	err := row.Scan(&k.ID, &k.UserID, &k.Name, &k.Prefix, &k.Hash, &k.Scopes, &k.ExpiresAt, &k.RevokedAt, &k.LastUsedAt, &k.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrKeyNotFound
	}
	return &k, err
}

func (p *Postgres) Create(ctx context.Context, k *domain.Key) error {
	_, err := p.db.Exec(ctx, `INSERT INTO guard_api_key (id, user_id, name, prefix, hash, scopes, expires_at, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, k.ID, k.UserID, k.Name, k.Prefix, k.Hash, k.Scopes, k.ExpiresAt, k.CreatedAt)
	if pgerr.IsForeignKeyViolation(err) || pgerr.IsInvalidText(err) {
		return domain.ErrOwnerNotFound
	}
	return err
}

func (p *Postgres) ByHash(ctx context.Context, hash string) (*domain.Key, error) {
	return scanKey(p.db.QueryRow(ctx, `SELECT `+keyColumns+` FROM guard_api_key WHERE hash=$1`, hash))
}

func (p *Postgres) ListByUser(ctx context.Context, userID string) ([]domain.Key, error) {
	out := []domain.Key{}
	if userID == "" {
		return out, nil
	}
	rows, err := p.db.Query(ctx, `SELECT `+keyColumns+` FROM guard_api_key WHERE user_id=$1 ORDER BY created_at DESC`, userID)
	if pgerr.IsInvalidText(err) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *k)
	}
	return out, rows.Err()
}

func (p *Postgres) Revoke(ctx context.Context, userID, id string, at time.Time) error {
	if _, err := uuid.Parse(id); err != nil {
		return domain.ErrKeyNotFound
	}
	if userID == "" {
		return domain.ErrKeyNotFound
	}
	tag, err := p.db.Exec(ctx, `UPDATE guard_api_key SET revoked_at=COALESCE(revoked_at,$3) WHERE id=$1 AND user_id=$2`, id, userID, at)
	if pgerr.IsInvalidText(err) {
		return domain.ErrKeyNotFound
	}
	if err == nil && tag.RowsAffected() == 0 {
		return domain.ErrKeyNotFound
	}
	return err
}

func (p *Postgres) RevokeAllByUser(ctx context.Context, userID string, at time.Time) error {
	if userID == "" {
		return nil
	}
	_, err := p.db.Exec(ctx, `UPDATE guard_api_key SET revoked_at=$2 WHERE user_id=$1 AND revoked_at IS NULL`, userID, at)
	if pgerr.IsInvalidText(err) {
		return nil
	}
	return err
}

func (p *Postgres) TouchLastUsed(ctx context.Context, id string, at time.Time) error {
	_, err := p.db.Exec(ctx, `UPDATE guard_api_key SET last_used_at=$2 WHERE id=$1`, id, at)
	return err
}

// Memory is an in-process Repository for tests.
type Memory struct {
	mu   sync.Mutex
	keys map[string]domain.Key
}

func NewMemory() *Memory { return &Memory{keys: map[string]domain.Key{}} }

func (m *Memory) Create(_ context.Context, k *domain.Key) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[k.ID] = *k
	return nil
}

func (m *Memory) ByHash(_ context.Context, hash string) (*domain.Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range m.keys {
		if k.Hash == hash {
			return &k, nil
		}
	}
	return nil, domain.ErrKeyNotFound
}

func (m *Memory) ListByUser(_ context.Context, userID string) ([]domain.Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []domain.Key{}
	for _, k := range m.keys {
		if k.UserID == userID {
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (m *Memory) Revoke(_ context.Context, userID, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.keys[id]
	if !ok || k.UserID != userID {
		return domain.ErrKeyNotFound
	}
	if k.RevokedAt == nil {
		k.RevokedAt = &at
		m.keys[id] = k
	}
	return nil
}

func (m *Memory) RevokeAllByUser(_ context.Context, userID string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, k := range m.keys {
		if k.UserID == userID && k.RevokedAt == nil {
			k.RevokedAt = &at
			m.keys[id] = k
		}
	}
	return nil
}

func (m *Memory) TouchLastUsed(_ context.Context, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if k, ok := m.keys[id]; ok {
		k.LastUsedAt = &at
		m.keys[id] = k
	}
	return nil
}
