package infrastructure

import (
	"context"
	"sync"

	"github.com/bakhod1r/guard/access/domain"
)

// superAdminLockKey is the pg advisory lock key shared by every Guard
// instance on a database ("guard_sa" as a big-endian int64).
const superAdminLockKey int64 = 0x67756172645f7361

// superAdminLockTimeout bounds how long a caller waits for the lock in
// PostgreSQL, even when its context has no deadline.
const superAdminLockTimeout = "10s"

// ctxMutex is a mutex whose Lock gives up when ctx ends. Zero value is ready.
type ctxMutex struct {
	once sync.Once
	ch   chan struct{}
}

func (m *ctxMutex) lock(ctx context.Context) error {
	m.once.Do(func() { m.ch = make(chan struct{}, 1) })
	select {
	case m.ch <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *ctxMutex) unlock() { <-m.ch }

// LockSuperAdmins serialises super admin shrinking operations in this store.
func (m *Memory) LockSuperAdmins(ctx context.Context, fn func(context.Context) error) error {
	if err := m.sa.lock(ctx); err != nil {
		return err
	}
	defer m.sa.unlock()
	return fn(ctx)
}

// LockSuperAdmins holds a transaction-scoped advisory lock on a dedicated
// connection while fn runs, so every instance on the database is excluded.
// The transaction is always rolled back: that releases the lock and fn's own
// writes (on other connections) are unaffected. If the lock connection dies
// mid-fn PostgreSQL releases the lock early; fn's writes stay individually
// atomic but exclusion is lost for that window.
func (r *Postgres) LockSuperAdmins(ctx context.Context, fn func(context.Context) error) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true)`, superAdminLockTimeout); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, superAdminLockKey); err != nil {
		return err
	}
	return fn(ctx)
}

// LockSuperAdmins delegates to the origin; without an origin lock fn runs
// directly and the application service's process lock still applies.
func (c *Cached) LockSuperAdmins(ctx context.Context, fn func(context.Context) error) error {
	if l, ok := c.RoleRepository.(domain.SuperAdminLocker); ok {
		return l.LockSuperAdmins(ctx, fn)
	}
	return fn(ctx)
}
