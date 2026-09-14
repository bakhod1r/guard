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
	sess, tok := domain.New(in.UserID, now, s.policy)
	sess.IP, sess.UserAgent, sess.Metadata = in.IP, in.UserAgent, in.Metadata
	if err := s.save(ctx, sess, sess.TTL(now, s.policy)); err != nil {
		return nil, "", err
	}
	return sess, tok, nil
}

// save persists a new session and enforces Policy.MaxPerUser. Repositories
// implementing domain.LimitedSaver do it atomically; otherwise eviction is
// best-effort and the new session is rolled back if it fails.
func (s *Service) save(ctx context.Context, sess *domain.Session, ttl time.Duration) error {
	limit := s.policy.MaxPerUser
	if ls, ok := s.repo.(domain.LimitedSaver); ok && limit > 0 {
		return ls.SaveLimited(ctx, sess, ttl, limit)
	}
	if err := s.repo.Save(ctx, sess, ttl); err != nil || limit <= 0 {
		return err
	}
	all, err := s.repo.ListByUser(ctx, sess.UserID)
	if err == nil {
		for _, id := range domain.Evict(all, limit, sess.ID) {
			if err = s.repo.Delete(ctx, id); err != nil {
				break
			}
		}
	}
	if err != nil {
		_ = s.repo.Delete(ctx, sess.ID)
	}
	return err
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
	ttl := sess.TTL(now, s.policy)
	if t, ok := s.repo.(domain.Toucher); ok {
		err = t.Touch(ctx, sess, ttl)
	} else {
		err = s.repo.Save(ctx, sess, ttl)
	}
	if err != nil {
		return nil, err
	}
	return sess, nil
}

// Rotate replaces a session's token (e.g. after login or privilege change)
// keeping CreatedAt, ExpiresAt and metadata. The new session is saved before
// the old one is deleted; if deleting the old one fails the new one is removed.
func (s *Service) Rotate(ctx context.Context, tok domain.Token) (*domain.Session, domain.Token, error) {
	if tok == "" {
		return nil, "", domain.ErrSessionNotFound
	}
	if taker, ok := s.repo.(domain.Taker); ok {
		return s.rotateTaken(ctx, taker, tok)
	}
	old, err := s.repo.Get(ctx, tok.ID())
	if err != nil {
		return nil, "", err
	}
	now := s.now().UTC()
	if err := old.Valid(now, s.policy); err != nil {
		_ = s.repo.Delete(ctx, old.ID)
		return nil, "", err
	}
	next := *old
	newTok := domain.NewToken()
	next.ID = newTok.ID()
	next.Touch(now)
	if err := s.repo.Save(ctx, &next, next.TTL(now, s.policy)); err != nil {
		return nil, "", err
	}
	if err := s.repo.Delete(ctx, old.ID); err != nil {
		_ = s.repo.Delete(ctx, next.ID)
		return nil, "", err
	}
	return &next, newTok, nil
}

// rotateTaken claims the old session atomically, so two concurrent rotations
// of one token cannot both succeed. If saving the new session fails the old
// one is put back.
func (s *Service) rotateTaken(ctx context.Context, taker domain.Taker, tok domain.Token) (*domain.Session, domain.Token, error) {
	old, err := taker.Take(ctx, tok.ID())
	if err != nil {
		return nil, "", err
	}
	now := s.now().UTC()
	if err := old.Valid(now, s.policy); err != nil {
		return nil, "", err
	}
	next := *old
	newTok := domain.NewToken()
	next.ID = newTok.ID()
	next.Touch(now)
	if err := s.repo.Save(ctx, &next, next.TTL(now, s.policy)); err != nil {
		_ = s.repo.Save(ctx, old, old.TTL(now, s.policy))
		return nil, "", err
	}
	return &next, newTok, nil
}

func (s *Service) Revoke(ctx context.Context, id domain.ID) error { return s.repo.Delete(ctx, id) }

func (s *Service) RevokeAll(ctx context.Context, userID string) error {
	return s.repo.DeleteByUser(ctx, userID)
}

func (s *Service) List(ctx context.Context, userID string) ([]*domain.Session, error) {
	return s.repo.ListByUser(ctx, userID)
}
