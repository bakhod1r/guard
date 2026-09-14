package application

import (
	"context"
	"errors"
	"strings"

	"github.com/bakhod1r/guard/access/domain"
)

// Route is an HTTP route registered by the host application.
type Route struct{ Method, Path string }

// RouteSeed reports what SeedRoutes did.
type RouteSeed struct {
	Permissions []domain.Permission // one per distinct derived code, in route order
	Skipped     []Route             // routes without a derivable permission
}

// SeedRoutes creates a permission for every route (idempotent) and makes sure
// superRole holds all of them; every other role gets nothing, so access is denied by default.
func (s *Service) SeedRoutes(ctx context.Context, routes []Route, prefix, superRole string) (RouteSeed, error) {
	var res RouteSeed
	seen := make(map[string]bool, len(routes))
	for _, r := range routes {
		p, err := domain.RoutePermission(r.Method, r.Path, prefix)
		if err != nil {
			res.Skipped = append(res.Skipped, r)
			continue
		}
		if seen[p.Code()] {
			continue
		}
		seen[p.Code()] = true
		created, err := s.CreatePermission(ctx, p.Code(), strings.ToUpper(strings.TrimSpace(r.Method))+" "+r.Path)
		if err != nil {
			return res, err
		}
		res.Permissions = append(res.Permissions, created)
	}
	if superRole == "" {
		return res, nil
	}
	role, err := s.Role(ctx, superRole)
	if errors.Is(err, domain.ErrRoleNotFound) {
		_, err = s.CreateRole(ctx, superRole, "Super administrator", "Full access to every route (autoseed)", true)
		return res, err
	}
	if err != nil || role.Wildcard {
		return res, err
	}
	for _, p := range res.Permissions {
		if err := s.GrantPermission(ctx, superRole, p.Code(), ""); err != nil {
			return res, err
		}
	}
	return res, nil
}
