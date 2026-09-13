// Command gin runs Guard's HTTP API on Gin.
//
//	DATABASE_URL=postgres://... REDIS_ADDR=localhost:6379 \
//	GUARD_ADMIN_EMAIL=admin@example.com GUARD_ADMIN_PASSWORD=change-me-now \
//	go run ./examples/gin
package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/bakhod1r/guard"
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

	pool, err := pgxpool.New(ctx, env("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/guard?sslmode=disable"))
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()
	rdb := redis.NewClient(&redis.Options{Addr: env("REDIS_ADDR", "localhost:6379"), Password: os.Getenv("REDIS_PASSWORD")})
	defer rdb.Close()

	// Stand-in for the host application's own user table. Guard never creates it.
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS users (id BIGSERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		log.Fatal(err)
	}

	g, err := guard.New(guard.Config{DB: pool, Redis: rdb, UserTable: "users", UserIDColumn: "id"})
	if err != nil {
		log.Fatal(err)
	}

	// 1. Detect users.id type and render migrations into the project, 2. apply them.
	dir := env("GUARD_MIGRATIONS_DIR", "./migrations/guard")
	written, err := g.WriteMigrations(ctx, dir)
	if err != nil {
		log.Fatal(err)
	}
	for _, f := range written {
		log.Printf("migration written: %s", f)
	}
	if err := g.Migrate(ctx, dir); err != nil {
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

	if email := os.Getenv("GUARD_ADMIN_EMAIL"); email != "" {
		var id string
		err := pool.QueryRow(ctx, `INSERT INTO users (email) VALUES (lower($1))
			ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email RETURNING id::text`, email).Scan(&id)
		if err != nil {
			log.Fatal(err)
		}
		if _, err := g.EnsureAdmin(ctx, id, email, os.Getenv("GUARD_ADMIN_PASSWORD")); err != nil {
			log.Fatal(err)
		}
	}

	opts := ginguard.Options{InsecureCookie: os.Getenv("GUARD_INSECURE_COOKIE") == "1", CreateUser: createUser}
	r := gin.Default()
	api := r.Group("/api")
	ginguard.Mount(api, g, opts)

	// Host app routes protected by Guard.
	api.GET("/reports", ginguard.RequirePermission(g, opts, "report.read"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"reports": []string{"q1", "q2"}, "by": ginguard.PrincipalFrom(c).User.Email})
	})

	log.Fatal(r.Run(env("ADDR", ":8080")))
}
