// Package application contains API key use cases.
package application

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/bakhod1r/guard/apikey/domain"
)

type Service struct {
	repo domain.Repository
	now  func() time.Time
}

func NewService(repo domain.Repository) *Service { return &Service{repo: repo, now: time.Now} }

func (s *Service) Issue(ctx context.Context, userID, name string, scopes []string, expiresAt *time.Time) (*domain.Key, domain.Token, error) {
	k, tok, err := domain.New(uuid.Must(uuid.NewV7()).String(), userID, name, scopes, expiresAt, s.now().UTC())
	if err != nil {
		return nil, "", err
	}
	if err := s.repo.Create(ctx, k); err != nil {
		return nil, "", err
	}
	return k, tok, nil
}

// Resolve validates a presented token. Every failure is ErrKeyInvalid.
func (s *Service) Resolve(ctx context.Context, tok domain.Token) (*domain.Key, error) {
	if !domain.LooksLikeKey(string(tok)) {
		return nil, domain.ErrKeyInvalid
	}
	k, err := s.repo.ByHash(ctx, tok.Hash())
	if err == domain.ErrKeyNotFound {
		return nil, domain.ErrKeyInvalid
	}
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	if err := k.Usable(now); err != nil {
		return nil, err
	}
	// Coarse last-used tracking: at most one write per minute per key.
	if k.LastUsedAt == nil || now.Sub(*k.LastUsedAt) > time.Minute {
		_ = s.repo.TouchLastUsed(ctx, k.ID, now)
		k.LastUsedAt = &now
	}
	return k, nil
}

func (s *Service) List(ctx context.Context, userID string) ([]domain.Key, error) {
	return s.repo.ListByUser(ctx, userID)
}

func (s *Service) Revoke(ctx context.Context, userID, id string) error {
	return s.repo.Revoke(ctx, userID, id, s.now().UTC())
}

func (s *Service) RevokeAll(ctx context.Context, userID string) error {
	return s.repo.RevokeAllByUser(ctx, userID, s.now().UTC())
}
