package application

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bakhod1r/guard/session/domain"
)

// takeRepo implements domain.Taker: atomic get-and-delete.
type takeRepo struct {
	*hookRepo
	takeErr error
}

func (r *takeRepo) Take(ctx context.Context, id domain.ID) (*domain.Session, error) {
	if r.takeErr != nil {
		return nil, r.takeErr
	}
	s, err := r.fakeRepo.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	delete(r.sessions, id)
	return s, nil
}

func TestRotateWithTakerClaimsOldSessionOnce(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	repo := &takeRepo{hookRepo: &hookRepo{fakeRepo: newFake()}}
	svc := svcWith(repo, &now, 0)
	old, oldTok, _ := svc.Start(ctx, StartInput{UserID: "u"})

	got, tok, err := svc.Rotate(ctx, oldTok)
	if err != nil || got.ID != tok.ID() || repo.sessions[old.ID] != nil || repo.sessions[got.ID] == nil {
		t.Fatalf("rotate: %+v %v %v", got, err, repo.sessions)
	}
	// A second, concurrent rotation of the same token loses the claim.
	if _, _, err := svc.Rotate(ctx, oldTok); !errors.Is(err, domain.ErrSessionNotFound) {
		t.Fatalf("second rotate: %v", err)
	}
	if len(repo.sessions) != 1 {
		t.Fatalf("live sessions: %d", len(repo.sessions))
	}
	for _, id := range repo.deleted {
		if id == old.ID {
			t.Fatal("taker path must not issue a separate delete")
		}
	}
}

func TestRotateWithTakerErrors(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	repo := &takeRepo{hookRepo: &hookRepo{fakeRepo: newFake()}}
	svc := svcWith(repo, &now, 0)

	s, tok, _ := svc.Start(ctx, StartInput{UserID: "u"})
	repo.takeErr = errBoom
	if _, _, err := svc.Rotate(ctx, tok); !errors.Is(err, errBoom) || repo.sessions[s.ID] == nil {
		t.Fatalf("take error: %v", err)
	}
	repo.takeErr = nil

	later := now.Add(2 * time.Minute)
	svc.now = func() time.Time { return later }
	if _, _, err := svc.Rotate(ctx, tok); !errors.Is(err, domain.ErrSessionExpired) || len(repo.sessions) != 0 {
		t.Fatalf("expired: %v %v", err, repo.sessions)
	}

	svc.now = func() time.Time { return now }
	s, tok, _ = svc.Start(ctx, StartInput{UserID: "u"})
	repo.saveErr = errBoom
	_, _, err := svc.Rotate(ctx, tok)
	repo.saveErr = nil
	if !errors.Is(err, errBoom) {
		t.Fatalf("save error: %v", err)
	}
	// Save of the new session failed; the old one could not be restored either
	// (same failing repo), so nothing is left — but the restore was attempted.
	s2, tok2, _ := svc.Start(ctx, StartInput{UserID: "u"})
	failOnce := &failFirstSave{takeRepo: repo}
	svc2 := svcWith(failOnce, &now, 0)
	if _, _, err := svc2.Rotate(ctx, tok2); !errors.Is(err, errBoom) || repo.sessions[s2.ID] == nil {
		t.Fatalf("restore after save failure: %v %v", err, repo.sessions)
	}
	_ = s
}

// failFirstSave fails the first Save only, so the restore of the old session succeeds.
type failFirstSave struct {
	*takeRepo
	saves int
}

func (f *failFirstSave) Save(ctx context.Context, s *domain.Session, ttl time.Duration) error {
	f.saves++
	if f.saves == 1 {
		return errBoom
	}
	return f.takeRepo.Save(ctx, s, ttl)
}
