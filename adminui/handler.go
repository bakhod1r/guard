package adminui

import (
	"cmp"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/bakhod1r/guard"
)

// Handler returns the whole admin panel as a single http.Handler, so hosts that
// are not built on Gin can serve it: net/http and chi mount it directly,
// Echo through echo.WrapHandler, Fiber through adaptor.HTTPHandler, and so on.
// The adapter modules shipped alongside Guard do this for you.
//
//	mux.Handle("/guard-admin/", adminui.Handler(g, adminui.Options{}))
//
// Options.Path (default "/guard-admin") stays part of every URL the panel
// renders, so mount it under exactly that prefix and do NOT strip it.
// Rendering still runs on an internal Gin engine; nothing of Gin leaks into the
// host router.
func Handler(g *guard.Guard, opts Options) http.Handler {
	engine := gin.New()
	engine.ContextWithFallback = true
	Mount(engine, g, opts)

	root := "/" + strings.Trim(cmp.Or(opts.Path, "/guard-admin"), "/")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A host mux serving the subtree "/guard-admin/" redirects the bare
		// "/guard-admin" to it; the panel's own root route has no trailing
		// slash, so normalise here instead of bouncing between the two.
		if r.URL.Path == root+"/" {
			r = r.Clone(r.Context())
			r.URL.Path = root
		}
		engine.ServeHTTP(w, r)
	})
}
