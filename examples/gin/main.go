// Command gin runs Guard's HTTP API on Gin, configured from a YAML file.
//
//	GUARD_CONFIG=examples/gin/guard.yaml \
//	DATABASE_URL=postgres://... REDIS_ADDR=localhost:6379 \
//	GUARD_SUPERADMIN_EMAIL=root@example.com GUARD_SUPERADMIN_PASSWORD=... \
//	GUARD_ADMIN_EMAIL=admin@example.com GUARD_ADMIN_PASSWORD=change-me-now \
//	go run ./examples/gin
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bakhod1r/guard"
	"github.com/bakhod1r/guard/adminui"
	"github.com/bakhod1r/guard/config"
	"github.com/bakhod1r/guard/ginguard"
	identitydomain "github.com/bakhod1r/guard/identity/domain"
	"github.com/bakhod1r/guard/kernel/pgerr"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	ctx := context.Background()

	cfg, err := config.Load(env("GUARD_CONFIG", "guard.yaml"))
	if err != nil {
		log.Fatal(err)
	}

	// The host application's own pool. Guard's pool is opened by cfg.Open.
	pool, err := pgxpool.New(ctx, cfg.Database.URL)
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()

	// Stand-in for the host application's own user table. Guard never creates it.
	// It must exist before cfg.Open: migrations detect the users.id type.
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS users (id BIGSERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		log.Fatal(err)
	}

	// Connects PostgreSQL + Redis and, with migrations.auto_apply, writes and applies migrations.
	g, err := cfg.Open(ctx)
	if err != nil {
		log.Fatal(err)
	}

	// Self-registration inserts a NEW host user only. Never link to an existing
	// row here: that would let anyone set a password for someone else's account.
	createUser := func(ctx context.Context, email string) (string, error) {
		var id string
		err := pool.QueryRow(ctx, `INSERT INTO users (email) VALUES (lower($1)) RETURNING id::text`, email).Scan(&id)
		if pgerr.IsUniqueViolation(err) {
			return "", identitydomain.ErrEmailTaken
		}
		return id, err
	}

	// Bootstrap accounts. The super admin is the only one who can grant or
	// revoke admin/super_admin later; Guard never removes or blocks the last one.
	bootstrap := func(emailKey, passwordKey string, ensure func(context.Context, string, string, string) (*guard.User, error)) {
		email := os.Getenv(emailKey)
		if email == "" {
			return
		}
		var id string
		err := pool.QueryRow(ctx, `INSERT INTO users (email) VALUES (lower($1))
			ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email RETURNING id::text`, email).Scan(&id)
		if err != nil {
			log.Fatal(err)
		}
		if _, err := ensure(ctx, id, email, os.Getenv(passwordKey)); err != nil {
			log.Fatalf("%s: %v", emailKey, err)
		}
	}
	bootstrap("GUARD_SUPERADMIN_EMAIL", "GUARD_SUPERADMIN_PASSWORD", g.EnsureSuperAdmin)
	bootstrap("GUARD_ADMIN_EMAIL", "GUARD_ADMIN_PASSWORD", g.EnsureAdmin)

	opts := cfg.HTTPOptions()
	opts.CreateUser = createUser
	if os.Getenv("GUARD_INSECURE_COOKIE") == "1" {
		opts.InsecureCookie = true
	}

	r := gin.Default()
	// Trust X-Forwarded-For only from listed proxies (comma-separated CIDRs/IPs).
	// Default: trust none, so clients cannot spoof their IP past per-IP rate limits.
	var proxies []string
	if v := os.Getenv("GUARD_TRUSTED_PROXIES"); v != "" {
		proxies = strings.Split(v, ",")
	}
	if err := r.SetTrustedProxies(proxies); err != nil {
		log.Fatalf("GUARD_TRUSTED_PROXIES: %v", err)
	}
	api := r.Group("/api")
	ginguard.Mount(api, g, opts)

	// Host app routes. Protect derives the permission from method + route:
	// GET /api/reports -> reports.read, POST /api/reports -> reports.create.
	app := api.Group("", ginguard.Protect(g, opts, "/api"))
	app.GET("/reports", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"reports": []string{"q1", "q2"}, "by": ginguard.PrincipalFrom(c).User.Email})
	})
	app.POST("/reports", func(c *gin.Context) {
		c.JSON(http.StatusCreated, gin.H{"created": true, "by": ginguard.PrincipalFrom(c).User.Email})
	})

	// Admin panel: users, roles, permissions, ABAC policies, sessions, API keys, audit.
	adminui.Mount(r, g, adminui.Options{Path: "/guard-admin", InsecureCookie: opts.InsecureCookie})

	// After every route is registered: sync one permission per route. admin and
	// super_admin get all, role "user" gets read on newly discovered routes, and
	// routes that disappeared are marked stale (grants are never revoked).
	if a, ok := cfg.AutoseedOptions(); ok {
		so := ginguard.SyncOptions{Prefix: a.Prefix, SkipPrefixes: a.Exclude}
		if a.SuperRole != "" && a.SuperRole != "admin" {
			so.FullRoles = []string{a.SuperRole}
		}
		res, err := ginguard.SyncRoutes(ctx, g, r.Routes(), so)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("routes: %d permissions (%d created), %d skipped, %d stale",
			len(res.Permissions), len(res.Created), len(res.Skipped), len(res.Stale))
	}

	log.Fatal(r.Run(env("ADDR", ":8080")))
}
