package infrastructure

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bakhod1r/guard/access/domain"
)

// PostgresRoutes stores the route registry in guard_route (migration 00006).
type PostgresRoutes struct{ db *pgxpool.Pool }

func NewPostgresRoutes(db *pgxpool.Pool) *PostgresRoutes { return &PostgresRoutes{db: db} }

func (r *PostgresRoutes) ListRoutes(ctx context.Context) ([]domain.RouteRecord, error) {
	return scanRoutes(r.db.Query(ctx, `SELECT method, path, permission, stale, last_seen_at FROM guard_route ORDER BY method, path`))
}

// SaveRoutes upserts all routes in one statement (no per-route round trip).
func (r *PostgresRoutes) SaveRoutes(ctx context.Context, routes []domain.RouteRecord, seenAt time.Time) error {
	if len(routes) == 0 {
		return nil
	}
	methods, paths, perms := make([]string, len(routes)), make([]string, len(routes)), make([]string, len(routes))
	for i, rt := range routes {
		methods[i], paths[i], perms[i] = rt.Method, rt.Path, rt.Permission
	}
	_, err := r.db.Exec(ctx, `INSERT INTO guard_route (method, path, permission, stale, first_seen_at, last_seen_at)
		SELECT m, p, perm, FALSE, $4, $4 FROM unnest($1::text[], $2::text[], $3::text[]) AS t(m, p, perm)
		ON CONFLICT (method, path) DO UPDATE SET permission = EXCLUDED.permission, stale = FALSE, last_seen_at = EXCLUDED.last_seen_at`,
		methods, paths, perms, seenAt)
	return err
}

func (r *PostgresRoutes) MarkStale(ctx context.Context, seenAt time.Time) ([]domain.RouteRecord, error) {
	out, err := scanRoutes(r.db.Query(ctx, `UPDATE guard_route SET stale = TRUE WHERE NOT stale AND last_seen_at < $1
		RETURNING method, path, permission, stale, last_seen_at`, seenAt))
	sortRoutes(out)
	return out, err
}

// scanRoutes takes Query's results directly; pgx may report a failed query either way.
func scanRoutes(rows pgx.Rows, err error) ([]domain.RouteRecord, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.RouteRecord{}
	for rows.Next() {
		var rt domain.RouteRecord
		if err := rows.Scan(&rt.Method, &rt.Path, &rt.Permission, &rt.Stale, &rt.SeenAt); err != nil {
			return nil, err
		}
		out = append(out, rt)
	}
	return out, rows.Err()
}
