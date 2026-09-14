package application

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bakhod1r/guard/session/domain"
)

// hookRepo adds failure switches and a hook that runs right after Get.
type hookRepo struct {
	*fakeRepo
	afterGet  func()
	listErr   error
	deleteErr error
	failID    domain.ID // when set, deleteErr applies only to this id
}

func (h *hookRepo) Get(ctx context.Context, id domain.ID) (*domain.Session, error) {
	s, err := h.fakeRepo.Get(ctx, id)
	if h.afterGet != nil {
		h.afterGet()
	}
	return s, err
}

func (h *hookRepo) ListByUser(ctx context.Context, uid string) ([]*domain.Session, error) {
	if h.listErr != nil {
		return nil, h.listErr
	}
	return h.fakeRepo.ListByUser(ctx, uid)
}

func (h *hookRepo) Delete(ctx context.Context, id domain.ID) error {
	if h.deleteErr != nil && (h.failID == "" || h.failID == id) {
		return h.deleteErr
	}
	return h.fakeRepo.Delete(ctx, id)
}

// touchRepo implements domain.Toucher with SET XX semantics.
type touchRepo struct {
	*hookRepo
	touches  int
	touchErr error
}

func (t *touchRepo) Touch(_ context.Context, s *domain.Session, ttl time.Duration) error {
	t.touches++
	if t.touchErr != nil {
		return t.touchErr
	}
	if _, ok := t.sessions[s.ID]; !ok {
		return domain.ErrSessionNotFound
	}
	t.lastTTL = ttl
	c := *s
	t.sessions[s.ID] = &c
	return nil
}

// limitedRepo implements domain.LimitedSaver.
type limitedRepo struct {
	*fakeRepo
	gotMax int
}

func (l *limitedRepo) SaveLimited(ctx context.Context, s *domain.Session, ttl time.Duration, limit int) error {
	l.gotMax = limit
	return l.Save(ctx, s, ttl)
}

func svcWith(repo domain.Repository, now *time.Time, limit int) *Service {
	s := NewService(repo, domain.Policy{IdleTimeout: time.Minute, AbsoluteTimeout: time.Hour, MaxPerUser: limit})
	s.now = func() time.Time { return *now }
	return s
}

func TestResolveDoesNotResurrectSessionRevokedMidRequest(t *testing.T) {
	now := time.Now()
	repo := &touchRepo{hookRepo: &hookRepo{fakeRepo: newFake()}}
	svc := svcWith(repo, &now, 0)
	ctx := context.Background()
	s, tok, _ := svc.Start(ctx, StartInput{UserID: "u"})
	repo.afterGet = func() { delete(repo.sessions, s.ID) } // Revoke lands between Get and Touch
	if _, err := svc.Resolve(ctx, tok); !errors.Is(err, domain.ErrSessionNotFound) {
		t.Fatalf("want not found got %v", err)
	}
	if _, ok := repo.sessions[s.ID]; ok || repo.touches != 1 {
		t.Fatalf("session resurrected (touches=%d)", repo.touches)
	}
}

func TestResolveUsesToucherAndPropagatesError(t *testing.T) {
	now := time.Now()
	repo := &touchRepo{hookRepo: &hookRepo{fakeRepo: newFake()}}
	svc := svcWith(repo, &now, 0)
	ctx := context.Background()
	_, tok, _ := svc.Start(ctx, StartInput{UserID: "u"})
	now = now.Add(20 * time.Second)
	if got, err := svc.Resolve(ctx, tok); err != nil || !got.LastSeenAt.Equal(now.UTC()) || repo.lastTTL != time.Minute {
		t.Fatalf("touch: %v %v", got, err)
	}
	repo.touchErr = errBoom
	if _, err := svc.Resolve(ctx, tok); !errors.Is(err, errBoom) {
		t.Fatalf("want boom got %v", err)
	}
}

func TestStartUsesLimitedSaver(t *testing.T) {
	now := time.Now()
	repo := &limitedRepo{fakeRepo: newFake()}
	if _, _, err := svcWith(repo, &now, 3).Start(context.Background(), StartInput{UserID: "u"}); err != nil || repo.gotMax != 3 {
		t.Fatalf("max=%d err=%v", repo.gotMax, err)
	}
	repo.saveErr = errBoom
	if _, _, err := svcWith(repo, &now, 3).Start(context.Background(), StartInput{UserID: "u"}); !errors.Is(err, errBoom) {
		t.Fatalf("want boom got %v", err)
	}
}

func TestStartFallbackEvictsLeastRecentlyUsed(t *testing.T) {
	now := time.Now()
	repo := &hookRepo{fakeRepo: newFake()}
	svc := svcWith(repo, &now, 2)
	ctx := context.Background()
	a, _, _ := svc.Start(ctx, StartInput{UserID: "u"})
	now = now.Add(time.Second)
	b, _, _ := svc.Start(ctx, StartInput{UserID: "u"})
	now = now.Add(time.Second)
	_, _, _ = svc.Start(ctx, StartInput{UserID: "other"})
	c, _, err := svc.Start(ctx, StartInput{UserID: "u"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := repo.sessions[a.ID]; ok {
		t.Fatal("oldest session not evicted")
	}
	if _, ok := repo.sessions[b.ID]; !ok {
		t.Fatal("b evicted")
	}
	if _, ok := repo.sessions[c.ID]; !ok {
		t.Fatal("new session evicted")
	}
}

func TestStartFallbackEvictionFailureRollsBackNewSession(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	repo := &hookRepo{fakeRepo: newFake()}
	svc := svcWith(repo, &now, 1)
	repo.listErr = errBoom
	if _, _, err := svc.Start(ctx, StartInput{UserID: "u"}); !errors.Is(err, errBoom) || len(repo.sessions) != 0 {
		t.Fatalf("list failure: err=%v left=%d", err, len(repo.sessions))
	}

	repo = &hookRepo{fakeRepo: newFake()}
	svc = svcWith(repo, &now, 1)
	old, _, _ := svc.Start(ctx, StartInput{UserID: "u"})
	repo.deleteErr, repo.failID = errBoom, old.ID
	if _, _, err := svc.Start(ctx, StartInput{UserID: "u"}); !errors.Is(err, errBoom) || len(repo.sessions) != 1 || repo.sessions[old.ID] == nil {
		t.Fatalf("delete failure: err=%v sessions=%v", err, repo.sessions)
	}
}

func TestRotate(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	repo := &hookRepo{fakeRepo: newFake()}
	svc := svcWith(repo, &now, 0)
	old, oldTok, _ := svc.Start(ctx, StartInput{UserID: "u", IP: "1.1.1.1", UserAgent: "ua", Metadata: map[string]string{"k": "v"}})
	now = now.Add(10 * time.Second)

	got, tok, err := svc.Rotate(ctx, oldTok)
	if err != nil || tok == oldTok || tok == "" || got.ID != tok.ID() || got.ID == old.ID {
		t.Fatalf("rotate: %+v %q %v", got, tok, err)
	}
	if !got.CreatedAt.Equal(old.CreatedAt) || !got.ExpiresAt.Equal(old.ExpiresAt) || got.UserID != "u" ||
		got.IP != "1.1.1.1" || got.UserAgent != "ua" || got.Metadata["k"] != "v" || !got.LastSeenAt.Equal(now.UTC()) {
		t.Fatalf("rotated fields: %+v", got)
	}
	if _, ok := repo.sessions[old.ID]; ok {
		t.Fatal("old session still stored")
	}
	if _, err := svc.Resolve(ctx, oldTok); !errors.Is(err, domain.ErrSessionNotFound) {
		t.Fatalf("old token resolves: %v", err)
	}
	if _, err := svc.Resolve(ctx, tok); err != nil {
		t.Fatalf("new token: %v", err)
	}
}

func TestRotateErrors(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	svc := svcWith(newFake(), &now, 0)
	if _, _, err := svc.Rotate(ctx, ""); !errors.Is(err, domain.ErrSessionNotFound) {
		t.Fatalf("empty: %v", err)
	}
	if _, _, err := svc.Rotate(ctx, "nope"); !errors.Is(err, domain.ErrSessionNotFound) {
		t.Fatalf("unknown: %v", err)
	}

	repo := &hookRepo{fakeRepo: newFake()}
	svc = svcWith(repo, &now, 0)
	s, tok, _ := svc.Start(ctx, StartInput{UserID: "u"})
	later := now.Add(2 * time.Minute)
	svc.now = func() time.Time { return later }
	if _, _, err := svc.Rotate(ctx, tok); !errors.Is(err, domain.ErrSessionExpired) || repo.sessions[s.ID] != nil {
		t.Fatalf("expired: %v", err)
	}

	svc.now = func() time.Time { return now }
	s, tok, _ = svc.Start(ctx, StartInput{UserID: "u"})
	repo.saveErr = errBoom
	if _, _, err := svc.Rotate(ctx, tok); !errors.Is(err, errBoom) || len(repo.sessions) != 1 {
		t.Fatalf("save: %v %d", err, len(repo.sessions))
	}
	repo.saveErr = nil
	repo.deleteErr = errBoom
	repo.failID = s.ID
	if _, _, err := svc.Rotate(ctx, tok); !errors.Is(err, errBoom) || len(repo.sessions) != 1 || repo.sessions[s.ID] == nil {
		t.Fatalf("delete old: err=%v sessions=%v", err, repo.sessions)
	}
}
