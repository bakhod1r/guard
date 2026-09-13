// Package application contains session use cases.
package application

import (
	"context"
	"time"

	"github.com/bakhod1r/guard/session/domain"
)

type Service struct {
	repo   domain.Repository
	policy domain.Policy
	now    func() time.Time
}

func NewService(repo domain.Repository, p domain.Policy) *Service {
	return &Service{repo: repo, policy: p, now: time.Now}
}

type StartInput struct {
	UserID    string
	IP        string
	UserAgent string
	Metadata  map[string]string
}

func (s *Service) Start(ctx context.Context, in StartInput) (*domain.Session, domain.Token, error) {
	now := s.now().UTC()
	sess, tok, err := domain.New(in.UserID, now, s.policy)
	if err != nil {
		return nil, "", err
	}
	sess.IP, sess.UserAgent, sess.Metadata = in.IP, in.UserAgent, in.Metadata
	if err := s.repo.Save(ctx, sess, sess.TTL(now, s.policy)); err != nil {
		return nil, "", err
	}
	return sess, tok, nil
}

// Resolve validates a token and slides its idle window.
func (s *Service) Resolve(ctx context.Context, tok domain.Token) (*domain.Session, error) {
	if tok == "" {
		return nil, domain.ErrSessionNotFound
	}
	sess, err := s.repo.Get(ctx, tok.ID())
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	if err := sess.Valid(now, s.policy); err != nil {
		_ = s.repo.Delete(ctx, sess.ID)
		return nil, err
	}
	sess.Touch(now)
	if err := s.repo.Save(ctx, sess, sess.TTL(now, s.policy)); err != nil {
		return nil, err
	}
	return sess, nil
}

func (s *Service) Revoke(ctx context.Context, id domain.ID) error { return s.repo.Delete(ctx, id) }

func (s *Service) RevokeAll(ctx context.Context, userID string) error {
	return s.repo.DeleteByUser(ctx, userID)
}

func (s *Service) List(ctx context.Context, userID string) ([]*domain.Session, error) {
	return s.repo.ListByUser(ctx, userID)
}
