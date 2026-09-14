package adminui

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/bakhod1r/guard"
)

// listRoutes is a variable only so tests can inject registry contents without PostgreSQL.
var listRoutes = func(ctx context.Context, g *guard.Guard) ([]guard.RouteRecord, error) {
	return g.ListRoutes(ctx)
}

func (a *app) registerRoutes(r *gin.RouterGroup) {
	r.GET("/routes", a.require("permission.read"), a.routesPage)
}

// routesPage lists the route registry filled by ginguard.SyncRoutes (read-only).
func (a *app) routesPage(c *gin.Context) {
	routes, err := listRoutes(c.Request.Context(), a.g)
	noRegistry := errors.Is(err, guard.ErrNoRouteRegistry)
	if err != nil && !noRegistry {
		a.rbacInternalError(c, err)
		return
	}
	stale := 0
	for _, rt := range routes {
		if rt.Stale {
			stale++
		}
	}
	a.render(c, http.StatusOK, "routes", "Routes", "routes", map[string]any{
		"Routes": routes, "NoRegistry": noRegistry, "Active": len(routes) - stale, "Stale": stale,
	})
}
