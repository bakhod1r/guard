package application

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bakhod1r/guard/apikey/domain"
	"github.com/bakhod1r/guard/apikey/infrastructure"
)

var errBoom = errors.New("boom")

// failingRepo wraps Memory and injects errors per method.
type failingRepo struct {
	*infrastructure.Memory
	createErr, byHashErr error
	touches              int
}

func (f *failingRepo) Create(ctx context.Context, k *domain.Key) error {
	if f.createErr != nil {
		return f.createErr
	}
	return f.Memory.Create(ctx, k)
}
func (f *failingRepo) ByHash(ctx context.Context, h string) (*domain.Key, error) {
	if f.byHashErr != nil {
		return nil, f.byHashErr
	}
	return f.Memory.ByHash(ctx, h)
}
func (f *failingRepo) TouchLastUsed(ctx context.Context, id string, at time.Time) error {
	f.touches++
	return f.Memory.TouchLastUsed(ctx, id, at)
}

func newSvc(now *time.Time) (*Service, *failingRepo) {
	repo := &failingRepo{Memory: infrastructure.NewMemory()}
	s := NewService(repo)
	s.now = func() time.Time { return *now }
	return s, repo
}

func TestIssue(t *testing.T) {
	now := time.Now()
	svc, repo := newSvc(&now)
	ctx := context.Background()
	if _, _, err := svc.Issue(ctx, "u", "", []string{"*"}, nil); !errors.Is(err, domain.ErrInvalidName) {
		t.Fatalf("validation: %v", err)
	}
	repo.createErr = errBoom
	if _, _, err := svc.Issue(ctx, "u", "ci", []string{"*"}, nil); !errors.Is(err, errBoom) {
		t.Fatalf("create error: %v", err)
	}
}

func TestResolvePaths(t *testing.T) {
	now := time.Now()
	svc, repo := newSvc(&now)
	ctx := context.Background()
	k, tok, err := svc.Issue(ctx, "u", "ci", []string{"*"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := svc.Resolve(ctx, "session-token"); !errors.Is(err, domain.ErrKeyInvalid) {
		t.Errorf("non key prefix: %v", err)
	}
	if _, err := svc.Resolve(ctx, domain.TokenPrefix+"unknown"); !errors.Is(err, domain.ErrKeyInvalid) {
		t.Errorf("not found: %v", err)
	}

	got, err := svc.Resolve(ctx, tok)
	if err != nil || got.ID != k.ID || got.LastUsedAt == nil || repo.touches != 1 {
		t.Fatalf("first resolve: %+v %v touches=%d", got, err, repo.touches)
	}
	now = now.Add(30 * time.Second)
	if _, err := svc.Resolve(ctx, tok); err != nil || repo.touches != 1 {
		t.Fatalf("within a minute must not touch: %v touches=%d", err, repo.touches)
	}
	now = now.Add(2 * time.Minute)
	if _, err := svc.Resolve(ctx, tok); err != nil || repo.touches != 2 {
		t.Fatalf("after a minute must touch: %v touches=%d", err, repo.touches)
	}

	if l, err := svc.List(ctx, "u"); err != nil || len(l) != 1 {
		t.Fatalf("list: %v %v", l, err)
	}
	if err := svc.Revoke(ctx, "u", k.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Resolve(ctx, tok); !errors.Is(err, domain.ErrKeyInvalid) {
		t.Errorf("unusable: %v", err)
	}
	if err := svc.RevokeAll(ctx, "u"); err != nil {
		t.Fatal(err)
	}

	repo.byHashErr = errBoom
	if _, err := svc.Resolve(ctx, tok); !errors.Is(err, errBoom) {
		t.Errorf("repo error: %v", err)
	}
}
