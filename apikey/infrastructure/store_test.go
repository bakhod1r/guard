package infrastructure

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bakhod1r/guard/apikey/domain"
)

func issue(t *testing.T, userID string, created time.Time) *domain.Key {
	t.Helper()
	k, _, err := domain.New(uuid.Must(uuid.NewV7()).String(), userID, "ci", []string{"report.read"}, nil, created)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// exerciseRepository runs the behaviour shared by every Repository implementation.
func exerciseRepository(t *testing.T, repo domain.Repository, owner, other string) {
	ctx := context.Background()
	t0 := time.Now().UTC().Truncate(time.Microsecond)
	older, newer := issue(t, owner, t0), issue(t, owner, t0.Add(time.Second))
	for _, k := range []*domain.Key{older, newer} {
		if err := repo.Create(ctx, k); err != nil {
			t.Fatal(err)
		}
	}

	got, err := repo.ByHash(ctx, newer.Hash)
	if err != nil || got.ID != newer.ID || got.UserID != owner {
		t.Fatalf("ByHash: %+v %v", got, err)
	}
	if _, err := repo.ByHash(ctx, "nope"); !errors.Is(err, domain.ErrKeyNotFound) {
		t.Fatalf("ByHash missing: %v", err)
	}

	list, err := repo.ListByUser(ctx, owner)
	if err != nil || len(list) != 2 || list[0].ID != newer.ID {
		t.Fatalf("ListByUser order: %+v %v", list, err)
	}
	if list, err := repo.ListByUser(ctx, other); err != nil || len(list) != 0 || list == nil {
		t.Fatalf("ListByUser other: %+v %v", list, err)
	}

	at := t0.Add(time.Minute)
	if err := repo.TouchLastUsed(ctx, older.ID, at); err != nil {
		t.Fatal(err)
	}
	if err := repo.TouchLastUsed(ctx, uuid.NewString(), at); err != nil {
		t.Fatalf("touch missing: %v", err)
	}
	if got, _ := repo.ByHash(ctx, older.Hash); got.LastUsedAt == nil || !got.LastUsedAt.Equal(at) {
		t.Fatalf("last used: %+v", got.LastUsedAt)
	}

	if err := repo.Revoke(ctx, other, older.ID, at); !errors.Is(err, domain.ErrKeyNotFound) {
		t.Fatalf("revoke by non-owner: %v", err)
	}
	if err := repo.Revoke(ctx, owner, uuid.NewString(), at); !errors.Is(err, domain.ErrKeyNotFound) {
		t.Fatalf("revoke missing: %v", err)
	}
	if err := repo.Revoke(ctx, owner, older.ID, at); err != nil {
		t.Fatal(err)
	}
	if err := repo.Revoke(ctx, owner, older.ID, at.Add(time.Hour)); err != nil {
		t.Fatalf("second revoke: %v", err)
	}
	if got, _ := repo.ByHash(ctx, older.Hash); got.RevokedAt == nil || !got.RevokedAt.Equal(at) {
		t.Fatalf("revoke must keep first timestamp: %+v", got.RevokedAt)
	}

	if err := repo.RevokeAllByUser(ctx, owner, at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.ByHash(ctx, newer.Hash); got.RevokedAt == nil || !got.RevokedAt.Equal(at.Add(time.Hour)) {
		t.Fatalf("revoke all: %+v", got.RevokedAt)
	}
	if got, _ := repo.ByHash(ctx, older.Hash); !got.RevokedAt.Equal(at) {
		t.Fatalf("revoke all must not overwrite: %+v", got.RevokedAt)
	}
}

func TestMemoryRepository(t *testing.T) {
	exerciseRepository(t, NewMemory(), "u1", "u2")
}

func TestPostgresRepository(t *testing.T) {
	pool := freshDB(t)
	exerciseRepository(t, NewPostgres(pool), newUser(t, pool), newUser(t, pool))
}

func TestPostgresCreateUnknownOwner(t *testing.T) {
	pool := freshDB(t)
	repo := NewPostgres(pool)
	for _, owner := range []string{"999999", "abc"} {
		if err := repo.Create(context.Background(), issue(t, owner, time.Now())); !errors.Is(err, domain.ErrOwnerNotFound) {
			t.Errorf("owner %q: want ErrOwnerNotFound got %v", owner, err)
		}
	}
}

func TestPostgresInvalidIdentifiers(t *testing.T) {
	pool := freshDB(t)
	repo := NewPostgres(pool)
	ctx := context.Background()
	now := time.Now()

	for _, uid := range []string{"", "abc"} {
		if l, err := repo.ListByUser(ctx, uid); err != nil || l == nil || len(l) != 0 {
			t.Errorf("ListByUser(%q): %v %v", uid, l, err)
		}
		if err := repo.RevokeAllByUser(ctx, uid, now); err != nil {
			t.Errorf("RevokeAllByUser(%q): %v", uid, err)
		}
	}
	revokes := []struct{ name, uid, id string }{
		{"key id not a uuid", "1", "not-a-uuid"},
		{"empty user", "", uuid.NewString()},
		{"user id not bigint", "abc", uuid.NewString()},
	}
	for _, c := range revokes {
		if err := repo.Revoke(ctx, c.uid, c.id, now); !errors.Is(err, domain.ErrKeyNotFound) {
			t.Errorf("%s: want ErrKeyNotFound got %v", c.name, err)
		}
	}
}

func TestPostgresListByUserOutOfRangeIDIsError(t *testing.T) {
	pool := freshDB(t)
	if _, err := NewPostgres(pool).ListByUser(context.Background(), "99999999999999999999"); err == nil {
		t.Fatal("want numeric out of range error")
	}
}

func TestPostgresStorageErrorsPropagate(t *testing.T) {
	pool := freshDB(t)
	repo := NewPostgres(pool)
	ctx := context.Background()
	uid := newUser(t, pool)
	pool.Close()
	now := time.Now()
	checks := map[string]func() error{
		"Create":          func() error { return repo.Create(ctx, issue(t, uid, now)) },
		"ByHash":          func() error { _, err := repo.ByHash(ctx, "x"); return err },
		"ListByUser":      func() error { _, err := repo.ListByUser(ctx, uid); return err },
		"Revoke":          func() error { return repo.Revoke(ctx, uid, uuid.NewString(), now) },
		"RevokeAllByUser": func() error { return repo.RevokeAllByUser(ctx, uid, now) },
		"TouchLastUsed":   func() error { return repo.TouchLastUsed(ctx, uuid.NewString(), now) },
	}
	for name, fn := range checks {
		if err := fn(); err == nil || errors.Is(err, domain.ErrKeyNotFound) || errors.Is(err, domain.ErrOwnerNotFound) {
			t.Errorf("%s: want storage error got %v", name, err)
		}
	}
}
