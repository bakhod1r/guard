package application

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bakhod1r/guard/session/domain"
)

type fakeRevoker struct {
	families []string
	users    []string
	err      error
}

func (r *fakeRevoker) RevokeFamily(_ context.Context, family string) error {
	r.families = append(r.families, family)
	return r.err
}

func (r *fakeRevoker) RevokeUser(_ context.Context, userID string, _ time.Time) error {
	r.users = append(r.users, userID)
	return r.err
}

type failDelete struct{ *fakeRepo }

func (failDelete) Delete(context.Context, domain.ID) error { return errBoom }

func TestPolicyAndSetRevoker(t *testing.T) {
	p := domain.Policy{IdleTimeout: time.Minute, AbsoluteTimeout: time.Hour}
	s := NewService(newFake(), p)
	if s.Policy() != p {
		t.Fatalf("policy: %+v", s.Policy())
	}
	s.SetRevoker(&fakeRevoker{})
	if s.revoker == nil {
		t.Fatal("revoker not set")
	}
	s.SetRevoker(nil)
	if s.revoker != nil {
		t.Fatal("revoker not removed")
	}
}

func TestStartWithRevokerAddsFamilyAndKeepsMetadata(t *testing.T) {
	now := time.Now()
	repo := newFake()
	s := newSvc(repo, &now)
	s.SetRevoker(&fakeRevoker{})
	in := map[string]string{"k": "v"}
	sess, _, err := s.Start(context.Background(), StartInput{UserID: "u", Metadata: in})
	if err != nil {
		t.Fatal(err)
	}
	if sess.Metadata["k"] != "v" || len(sess.Metadata[domain.FamilyKey]) != 32 {
		t.Fatalf("metadata: %+v", sess.Metadata)
	}
	if _, ok := in[domain.FamilyKey]; ok {
		t.Fatal("caller's metadata map must not be mutated")
	}
	if sess.Family() != sess.Metadata[domain.FamilyKey] {
		t.Fatalf("family: %q", sess.Family())
	}
}

func TestRevokeWithRevoker(t *testing.T) {
	now := time.Now()
	repo := newFake()
	s := newSvc(repo, &now)
	rv := &fakeRevoker{}
	s.SetRevoker(rv)
	sess, _, _ := s.Start(context.Background(), StartInput{UserID: "u"})
	if err := s.Revoke(context.Background(), sess.ID); err != nil {
		t.Fatal(err)
	}
	if len(rv.families) != 1 || rv.families[0] != sess.Family() {
		t.Fatalf("families: %v", rv.families)
	}

	// unknown session: deleted, no family to revoke
	if err := s.Revoke(context.Background(), "missing"); err != nil || len(rv.families) != 1 {
		t.Fatalf("missing: %v %v", err, rv.families)
	}

	// revoker failure surfaces
	sess2, _, _ := s.Start(context.Background(), StartInput{UserID: "u"})
	rv.err = errBoom
	if err := s.Revoke(context.Background(), sess2.ID); !errors.Is(err, errBoom) {
		t.Fatalf("revoker err: %v", err)
	}
}

func TestRevokeDeleteErrorSkipsRevoker(t *testing.T) {
	now := time.Now()
	repo := failDelete{newFake()}
	s := newSvc(repo, &now)
	rv := &fakeRevoker{}
	s.SetRevoker(rv)
	sess, _, _ := s.Start(context.Background(), StartInput{UserID: "u"})
	if err := s.Revoke(context.Background(), sess.ID); !errors.Is(err, errBoom) {
		t.Fatalf("err: %v", err)
	}
	if len(rv.families) != 0 {
		t.Fatalf("revoker must not run when delete fails: %v", rv.families)
	}
}

func TestRevokeAllWithRevoker(t *testing.T) {
	now := time.Now()
	repo := newFake()
	s := newSvc(repo, &now)
	rv := &fakeRevoker{}
	s.SetRevoker(rv)
	_, _, _ = s.Start(context.Background(), StartInput{UserID: "u"})
	if err := s.RevokeAll(context.Background(), "u"); err != nil {
		t.Fatal(err)
	}
	if len(rv.users) != 1 || len(repo.sessions) != 0 {
		t.Fatalf("users %v sessions %d", rv.users, len(repo.sessions))
	}

	// revoker failure keeps the sessions for a retry
	_, _, _ = s.Start(context.Background(), StartInput{UserID: "u"})
	rv.err = errBoom
	if err := s.RevokeAll(context.Background(), "u"); !errors.Is(err, errBoom) || len(repo.sessions) != 1 {
		t.Fatalf("err %v sessions %d", err, len(repo.sessions))
	}
}
