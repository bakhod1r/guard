package application

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bakhod1r/guard/session/domain"
)

var errBoom = errors.New("boom")

type fakeRepo struct {
	sessions map[domain.ID]*domain.Session
	saveErr  error
	deleted  []domain.ID
	lastTTL  time.Duration
}

func newFake() *fakeRepo { return &fakeRepo{sessions: map[domain.ID]*domain.Session{}} }

func (f *fakeRepo) Save(_ context.Context, s *domain.Session, ttl time.Duration) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	f.lastTTL = ttl
	c := *s
	f.sessions[s.ID] = &c
	return nil
}
func (f *fakeRepo) Get(_ context.Context, id domain.ID) (*domain.Session, error) {
	s, ok := f.sessions[id]
	if !ok {
		return nil, domain.ErrSessionNotFound
	}
	c := *s
	return &c, nil
}
func (f *fakeRepo) Delete(_ context.Context, id domain.ID) error {
	f.deleted = append(f.deleted, id)
	delete(f.sessions, id)
	return nil
}
func (f *fakeRepo) ListByUser(_ context.Context, uid string) ([]*domain.Session, error) {
	var out []*domain.Session
	for _, s := range f.sessions {
		if s.UserID == uid {
			out = append(out, s)
		}
	}
	return out, nil
}
func (f *fakeRepo) DeleteByUser(_ context.Context, uid string) error {
	for id, s := range f.sessions {
		if s.UserID == uid {
			delete(f.sessions, id)
		}
	}
	return nil
}

func newSvc(repo domain.Repository, now *time.Time) *Service {
	s := NewService(repo, domain.Policy{IdleTimeout: time.Minute, AbsoluteTimeout: time.Hour})
	s.now = func() time.Time { return *now }
	return s
}

func TestStartPropagatesSaveError(t *testing.T) {
	now := time.Now()
	repo := newFake()
	repo.saveErr = errBoom
	if _, _, err := newSvc(repo, &now).Start(context.Background(), StartInput{UserID: "u"}); !errors.Is(err, errBoom) {
		t.Fatalf("want boom got %v", err)
	}
}

func TestResolveEmptyTokenIsNotFound(t *testing.T) {
	now := time.Now()
	if _, err := newSvc(newFake(), &now).Resolve(context.Background(), ""); !errors.Is(err, domain.ErrSessionNotFound) {
		t.Fatal(err)
	}
}

func TestResolveExpiredDeletesSession(t *testing.T) {
	now := time.Now()
	repo := newFake()
	svc := newSvc(repo, &now)
	s, tok, err := svc.Start(context.Background(), StartInput{UserID: "u"})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := svc.Resolve(context.Background(), tok); !errors.Is(err, domain.ErrSessionExpired) {
		t.Fatalf("want expired got %v", err)
	}
	if len(repo.deleted) != 1 || repo.deleted[0] != s.ID {
		t.Fatalf("expired session not deleted: %v", repo.deleted)
	}
}

func TestResolveSlidesAndPropagatesSaveError(t *testing.T) {
	now := time.Now()
	repo := newFake()
	svc := newSvc(repo, &now)
	_, tok, _ := svc.Start(context.Background(), StartInput{UserID: "u", Metadata: map[string]string{"k": "v"}})
	now = now.Add(30 * time.Second)
	got, err := svc.Resolve(context.Background(), tok)
	if err != nil || !got.LastSeenAt.Equal(now.UTC()) || repo.lastTTL != time.Minute {
		t.Fatalf("slide: %+v %v ttl=%v", got, err, repo.lastTTL)
	}
	repo.saveErr = errBoom
	if _, err := svc.Resolve(context.Background(), tok); !errors.Is(err, errBoom) {
		t.Fatalf("want boom got %v", err)
	}
}

func TestRevokeListRevokeAll(t *testing.T) {
	now := time.Now()
	repo := newFake()
	svc := newSvc(repo, &now)
	ctx := context.Background()
	a, _, _ := svc.Start(ctx, StartInput{UserID: "u"})
	svc.Start(ctx, StartInput{UserID: "u"})
	if l, _ := svc.List(ctx, "u"); len(l) != 2 {
		t.Fatalf("want 2 got %d", len(l))
	}
	if err := svc.Revoke(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.RevokeAll(ctx, "u"); err != nil {
		t.Fatal(err)
	}
	if l, _ := svc.List(ctx, "u"); len(l) != 0 {
		t.Fatalf("want 0 got %d", len(l))
	}
}

func TestResolveUnknownTokenPropagatesRepoError(t *testing.T) {
	now := time.Now()
	if _, err := newSvc(newFake(), &now).Resolve(context.Background(), "nope"); !errors.Is(err, domain.ErrSessionNotFound) {
		t.Fatalf("want not found got %v", err)
	}
}
