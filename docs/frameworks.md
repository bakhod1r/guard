# Frameworks

Guard's HTTP layer is `httpguard`: plain `net/http`, no framework dependency.
Everything else is a thin translation of it.

| Framework | Package | Extra dependency |
|---|---|---|
| net/http (`ServeMux`) | `github.com/bakhod1r/guard/httpguard` | none |
| chi | `httpguard` + `Options.PathValue = chi.URLParam` | none |
| gorilla/mux | `httpguard` + `Options.PathValue` from `mux.Vars` | none |
| httprouter | `httpguard` + `Options.PathValue` from `httprouter.ParamsFromContext` | none |
| negroni, alice, any `http.Handler` chain | `httpguard` middleware as is | none |
| Gin | `github.com/bakhod1r/guard/ginguard` | gin (already required) |
| Echo | `github.com/bakhod1r/guard/adapters/echo` | echo/v4 |
| Fiber | `github.com/bakhod1r/guard/adapters/fiber` | fiber/v2 |
| Iris | `github.com/bakhod1r/guard/adapters/iris` | iris/v12 |
| Hertz | `github.com/bakhod1r/guard/adapters/hertz` | hertz |
| Beego | `github.com/bakhod1r/guard/adapters/beego` | beego/v2 |

Each adapter lives in its own Go module, so `go get github.com/bakhod1r/guard`
never pulls Echo, Fiber, Iris, Hertz or Beego into your build.

Every adapter offers the same surface:

- `Mount(router, g, opts, prefix...)` — the whole REST API (`/auth/*`, `/guard/*`).
- `MountAdmin(router, g, adminui.Options{})` — the HTML admin panel.
- `Authenticate`, `RequireAuth`, `RequireSession`, `Require`, `RequirePermission`,
  `RateLimit`, `Protect` — middleware for the host's own routes.
- `PrincipalFrom(ctx)` — the authenticated caller inside a handler.
- `ParamResource(name)` — ABAC resource id taken from the framework's own path
  parameters.
- `Wrap(opts, build)` — escape hatch: turn any `httpguard` middleware into a
  framework handler.

## net/http

```go
mux := http.NewServeMux()
httpguard.Mount(mux, g, httpguard.Options{AuthPath: "/api/auth", AdminPath: "/api/guard"})
mux.Handle("/guard-admin/", adminui.Handler(g, adminui.Options{}))

mux.Handle("GET /api/invoices/{id}",
    httpguard.RequirePermission(g, opts, "invoice.read")(invoiceHandler))
```

`httpguard.Handler(g, opts)` returns the same routes as a single `http.Handler`,
for mounting under a prefix (`http.StripPrefix`, `chi.Mount`, `mux.PathPrefix`).

Route-derived permissions work the same as on Gin; net/http has no route
registry, so hand the table over yourself:

```go
api := http.NewServeMux()
rt := httpguard.NewCollector(api)
rt.Handle("GET /api/reports/{id}", reports)
httpguard.Autoseed(ctx, g, rt.Routes(), httpguard.AutoseedOptions{Prefix: "/api"})

// ProtectMux resolves the pattern the request will match, then checks the
// permission derived from it. Protect (the middleware form) goes around a
// single route's handler, where the pattern is already on the request.
srv.Handle("/api/", httpguard.ProtectMux(g, opts, "/api", api))
```

## chi / gorilla/mux / httprouter

Guard reads path parameters through `Options.PathValue`, so plug in the router's
own accessor and everything else (including `ParamResource` and ABAC self
policies) works unchanged:

```go
opts.PathValue    = func(r *http.Request, name string) string { return chi.URLParam(r, name) }
opts.RoutePattern = func(r *http.Request) string { return chi.RouteContext(r.Context()).RoutePattern() }
```

Guard's own routes are served by an internal `ServeMux`, so mount them with the
default (`nil`) `PathValue`; see `adapters/nethttp/compat_test.go` for the three
routers wired end to end.

## Echo

```go
e := echo.New()
echoguard.Mount(e, g, opts, "/api")
echoguard.MountAdmin(e, g, adminui.Options{})
e.GET("/api/invoices/:id", handler, echoguard.RequirePermission(g, opts, "invoice.read"))
```

## Fiber

```go
app := fiber.New()
fiberguard.Mount(app, g, opts, "/api")
fiberguard.MountAdmin(app, g, adminui.Options{})
app.Get("/api/invoices/:id", fiberguard.RequirePermission(g, opts, "invoice.read"), handler)
```

## Iris

```go
app := iris.New()
irisguard.Mount(app, g, opts, "/api")
irisguard.MountAdmin(app, g, adminui.Options{})
app.Get("/api/invoices/{id}", irisguard.RequirePermission(g, opts, "invoice.read"), handler)
```

## Hertz

```go
h := server.Default()
hertzguard.Mount(h, g, opts, "/api")
hertzguard.MountAdmin(h, g, adminui.Options{})
h.GET("/api/invoices/:id", hertzguard.RequirePermission(g, opts, "invoice.read"), handler)
```

## Beego

Beego keeps one global application, so Mount takes no router:

```go
beegoguard.Mount(g, opts, "/api")
beegoguard.MountAdmin(g, adminui.Options{})
web.InsertFilter("/api/invoices/*", web.BeforeExec,
    beegoguard.RequirePermission(g, opts, "invoice.read"), web.WithReturnOnOutput(false))
```

Beego filters run before routing when placed at `BeforeRouter`; use `BeforeExec`
so `ParamResource` sees the route's `:id`.

## Admin panel on any framework

`adminui.Handler(g, opts)` is the panel as one `http.Handler`. Mount it at
exactly `adminui.Options.Path` (default `/guard-admin`) and do **not** strip the
prefix — the rendered links are absolute. The panel itself still renders on an
internal Gin engine; nothing of Gin reaches your router.

## Client IP behind a proxy

`httpguard` reads `RemoteAddr` by default. Behind a proxy you control, set
`Options.TrustForwardedFor = true` (left-most `X-Forwarded-For` entry) or supply
`Options.ClientIP`. The Echo, Fiber, Iris, Hertz and Beego adapters use the
framework's own resolver instead.

## Working on the adapters

The adapters are separate modules in `adapters/`, wired to this checkout by the
repository's `go.work`, so they build and test against the working tree:

```bash
make test-adapters            # all six
go test ./adapters/echo/      # one
```

Their `go.mod` files require a published `github.com/bakhod1r/guard` version.
Until a release carries `httpguard`, only the workspace build works; after
tagging, bump each adapter's requirement and run `go mod tidy` inside it so the
module resolves standalone for `go get`.
