package infrastructure

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"time"

	"github.com/bakhod1r/guard/session/domain"
	"github.com/bakhod1r/sessionx"
	"github.com/bakhod1r/sessionx/sqlstore"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

// PostgresSessions keeps login sessions in PostgreSQL through github.com/bakhod1r/sessionx/sqlstore (table guard_session),
// so they survive Redis restarts, evictions and flushes. It adapts sessionx.Store to the Repository interface and its
// optional Toucher, Taker and LimitedSaver capabilities.
//
// Guard's idle and absolute limits stay Guard's (its Policy, applied on Resolve): last_seen and expires_at carry them.
//
// legacy, when set, is the old Redis store: a session missing here is looked up there once and moved over, so switching
// stores does not sign anyone out. Drop it once the absolute session timeout has passed since the switch.
type PostgresSessions struct {
	pool   *pgxpool.Pool
	sql    *sql.DB
	store  *sqlstore.Store
	policy domain.Policy
	legacy domain.Repository
}

const sessionsTable = "guard_session"

// NewPostgresSessions stores sessions in pool. policy is the session policy the service runs with (its idle window decides
// whether a migrated legacy session is still alive); legacy may be nil.
func NewPostgresSessions(pool *pgxpool.Pool, policy domain.Policy, legacy domain.Repository) *PostgresSessions {
	db := stdlib.OpenDBFromPool(pool)
	return &PostgresSessions{pool: pool, sql: db, store: sqlstore.New(db, sqlstore.Options{Table: sessionsTable, Placeholder: sqlstore.Dollar}), policy: policy, legacy: legacy}
}

func toX(s *domain.Session) *sessionx.Session {
	// The User-Agent is parsed into brand / OS / browser / form factor and a human-or-bot verdict, so the stored session
	// says what opened it, not just the raw header.
	device, client := sessionx.DeviceFromUA(s.UserAgent)
	device.Raw = s.UserAgent
	x := &sessionx.Session{
		ID: string(s.ID), UserID: s.UserID, Status: sessionx.StatusActive,
		Device: device, Client: client, Network: sessionx.Network{IP: s.IP, Forwarded: s.Forwarded},
		Locale: s.Locale, LocaleSource: s.LocaleSource, RenewedAt: s.RenewedAt,
		CreatedAt: s.CreatedAt, LastSeen: s.LastSeenAt, ExpiresAt: s.ExpiresAt,
		Data: map[string]any{},
	}
	if len(s.Metadata) > 0 {
		meta := make(map[string]any, len(s.Metadata))
		for k, v := range s.Metadata {
			meta[k] = v
		}
		x.Data["metadata"] = meta
	}
	return x
}

func fromX(x *sessionx.Session) *domain.Session {
	s := &domain.Session{ID: domain.ID(x.ID), UserID: x.UserID, CreatedAt: x.CreatedAt, LastSeenAt: x.LastSeen,
		ExpiresAt: x.ExpiresAt, IP: x.Network.IP, UserAgent: x.Device.Raw, Forwarded: x.Network.Forwarded,
		Locale: x.Locale, LocaleSource: x.LocaleSource, RenewedAt: x.RenewedAt}
	if meta, ok := x.Data["metadata"].(map[string]any); ok && len(meta) > 0 {
		s.Metadata = make(map[string]string, len(meta))
		for k, v := range meta {
			if str, ok := v.(string); ok {
				s.Metadata[k] = str
			}
		}
	}
	return s
}

// live is a session Guard may still use (a revoked or expired row is final).
func live(x *sessionx.Session) bool { return !x.Status.Terminal() }

func (r *PostgresSessions) Save(ctx context.Context, s *domain.Session, _ time.Duration) error {
	err := r.store.Save(ctx, toX(s))
	if errors.Is(err, sessionx.ErrRevoked) || errors.Is(err, sessionx.ErrExpired) {
		return domain.ErrSessionNotFound
	}
	if err == nil {
		r.gc(ctx)
	}
	return err
}

// gc drops sessions past their absolute deadline; they are written rarely (sign-in, refresh), so this keeps the table small.
func (r *PostgresSessions) gc(ctx context.Context) { _, _ = r.store.GC(ctx, time.Now()) }

func (r *PostgresSessions) Get(ctx context.Context, id domain.ID) (*domain.Session, error) {
	x, err := r.store.Load(ctx, string(id))
	switch {
	case errors.Is(err, sessionx.ErrNotFound):
		if r.legacy != nil {
			return r.adopt(ctx, id)
		}
		return nil, domain.ErrSessionNotFound
	case err != nil:
		return nil, err
	case !live(x):
		return nil, domain.ErrSessionNotFound
	}
	return fromX(x), nil
}

// adopt moves a session from the legacy Redis store into Postgres.
func (r *PostgresSessions) adopt(ctx context.Context, id domain.ID) (*domain.Session, error) {
	s, err := r.legacy.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if s.TTL(time.Now().UTC(), r.policy) <= 0 {
		_ = r.legacy.Delete(ctx, id)
		return nil, domain.ErrSessionNotFound
	}
	if err := r.Save(ctx, s, 0); err != nil {
		return nil, err
	}
	_ = r.legacy.Delete(ctx, id)
	return s, nil
}

func (r *PostgresSessions) Delete(ctx context.Context, id domain.ID) error {
	if err := r.store.Delete(ctx, string(id)); err != nil {
		return err
	}
	if r.legacy != nil {
		return r.legacy.Delete(ctx, id)
	}
	return nil
}

func (r *PostgresSessions) ListByUser(ctx context.Context, userID string) ([]*domain.Session, error) {
	xs, err := r.store.ListByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.Session, 0, len(xs))
	seen := map[domain.ID]bool{}
	for _, x := range xs {
		if live(x) {
			s := fromX(x)
			out = append(out, s)
			seen[s.ID] = true
		}
	}
	if r.legacy != nil {
		old, err := r.legacy.ListByUser(ctx, userID)
		if err != nil {
			return nil, err
		}
		for _, s := range old {
			if !seen[s.ID] {
				out = append(out, s)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].LastSeenAt.After(out[j].LastSeenAt) })
	return out, nil
}

func (r *PostgresSessions) DeleteByUser(ctx context.Context, userID string) error {
	if _, err := r.store.DeleteByUser(ctx, userID); err != nil {
		return err
	}
	if r.legacy != nil {
		return r.legacy.DeleteByUser(ctx, userID)
	}
	return nil
}

// Touch slides last_seen only while the session still exists and is live, so a concurrent sign-out is not undone.
func (r *PostgresSessions) Touch(ctx context.Context, s *domain.Session, _ time.Duration) error {
	tag, err := r.pool.Exec(ctx, `UPDATE `+sessionsTable+` SET last_seen = $2 WHERE id = $1 AND status NOT IN ('revoked', 'expired')`,
		string(s.ID), s.LastSeenAt.UTC())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrSessionNotFound
	}
	return nil
}

// Take claims a session so only one caller can rotate it: the row is marked revoked in one statement (the winner sees one
// affected row), then removed.
func (r *PostgresSessions) Take(ctx context.Context, id domain.ID) (*domain.Session, error) {
	x, err := r.store.Load(ctx, string(id))
	switch {
	case errors.Is(err, sessionx.ErrNotFound):
		if t, ok := r.legacy.(domain.Taker); ok && r.legacy != nil {
			return t.Take(ctx, id)
		}
		return nil, domain.ErrSessionNotFound
	case err != nil:
		return nil, err
	case !live(x):
		return nil, domain.ErrSessionNotFound
	}
	tag, err := r.pool.Exec(ctx, `UPDATE `+sessionsTable+` SET status = 'revoked' WHERE id = $1 AND status NOT IN ('revoked', 'expired')`, string(id))
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, domain.ErrSessionNotFound
	}
	_ = r.store.Delete(ctx, string(id))
	return fromX(x), nil
}

// SaveLimited saves s and evicts the user's least recently used sessions beyond limit.
func (r *PostgresSessions) SaveLimited(ctx context.Context, s *domain.Session, ttl time.Duration, limit int) error {
	if err := r.Save(ctx, s, ttl); err != nil {
		return err
	}
	_, err := r.pool.Exec(ctx, `DELETE FROM `+sessionsTable+` WHERE user_id = $1 AND id IN (
		SELECT id FROM `+sessionsTable+` WHERE user_id = $1 AND id <> $2 AND status NOT IN ('revoked', 'expired')
		ORDER BY last_seen DESC, id DESC OFFSET $3)`, s.UserID, string(s.ID), max(limit-1, 0))
	return err
}
