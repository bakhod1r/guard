package infrastructure

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/bakhod1r/guard/access/domain"
)

// MemoryRoutes is an in-memory domain.RouteRegistry for tests and single-process use.
type MemoryRoutes struct {
	mu     sync.Mutex
	routes map[string]domain.RouteRecord
}

func NewMemoryRoutes() *MemoryRoutes {
	return &MemoryRoutes{routes: map[string]domain.RouteRecord{}}
}

func (m *MemoryRoutes) ListRoutes(context.Context) ([]domain.RouteRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]domain.RouteRecord, 0, len(m.routes))
	for _, r := range m.routes {
		out = append(out, r)
	}
	sortRoutes(out)
	return out, nil
}

func (m *MemoryRoutes) SaveRoutes(_ context.Context, routes []domain.RouteRecord, seenAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range routes {
		r.Stale, r.SeenAt = false, seenAt
		m.routes[r.Key()] = r
	}
	return nil
}

func (m *MemoryRoutes) MarkStale(_ context.Context, seenAt time.Time) ([]domain.RouteRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []domain.RouteRecord
	for k, r := range m.routes {
		if !r.Stale && r.SeenAt.Before(seenAt) {
			r.Stale = true
			m.routes[k] = r
			out = append(out, r)
		}
	}
	sortRoutes(out)
	return out, nil
}

func sortRoutes(rs []domain.RouteRecord) {
	sort.Slice(rs, func(i, j int) bool { return rs[i].Key() < rs[j].Key() })
}
