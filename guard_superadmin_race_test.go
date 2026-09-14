package guard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	accessdomain "github.com/bakhod1r/guard/access/domain"
	identitydomain "github.com/bakhod1r/guard/identity/domain"
	"github.com/bakhod1r/guard/kernel/migrations"
	sessionapp "github.com/bakhod1r/guard/session/application"
	sessioninfra "github.com/bakhod1r/guard/session/infrastructure"
)

// raceGuards returns two Guard instances (separate pools, like two app
// replicas) on a fresh database with host users 1..3; 1 and 2 are super admins.
func raceGuards(t *testing.T) (*Guard, *Guard) {
	t.Helper()
	dsn := os.Getenv("GUARD_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("GUARD_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "guard_sa_race_" + hex.EncodeToString(b)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	cfg, _ := pgxpool.ParseConfig(dsn)
	cfg.ConnConfig.Database = name
	pools := make([]*pgxpool.Pool, 2)
	for i := range pools {
		if pools[i], err = pgxpool.NewWithConfig(ctx, cfg.Copy()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, p := range pools {
			p.Close()
		}
		c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = admin.Exec(c, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
		admin.Close()
	})
	if _, err := pools[0].Exec(ctx, `CREATE TABLE users (id BIGSERIAL PRIMARY KEY); INSERT INTO users SELECT FROM generate_series(1,3)`); err != nil {
		t.Fatal(err)
	}
	ref, err := migrations.Detect(ctx, pools[0], "users", "id")
	if err != nil {
		t.Fatal(err)
	}
	if err := migrations.Up(ctx, pools[0], "", ref); err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: miniredis.RunT(t).Addr()})
	gs := make([]*Guard, 2)
	for i, p := range pools {
		if gs[i], err = New(Config{DB: p, Redis: rdb, PasswordHashParams: &PasswordHashParams{Memory: 19 * 1024, Time: 2, Threads: 1, SaltLen: 16, KeyLen: 32}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"1", "2"} {
		if _, err := gs[0].EnsureSuperAdmin(ctx, id, "sa"+id+"@example.com", saPW); err != nil {
			t.Fatal(err)
		}
	}
	return gs[0], gs[1]
}

// activeSuperAdmins counts super admins whose account can log in.
func activeSuperAdmins(t *testing.T, g *Guard) int {
	t.Helper()
	ctx := context.Background()
	ids, err := g.SuperAdmins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, id := range ids {
		if u, err := g.Identity.User(ctx, identitydomain.UserID(id)); err == nil && u.CanLogin() == nil {
			n++
		}
	}
	return n
}

func resetSuperAdmins(t *testing.T, g *Guard) {
	t.Helper()
	ctx := context.Background()
	for _, id := range []string{"1", "2"} {
		if err := g.Identity.SetStatus(ctx, identitydomain.UserID(id), identitydomain.StatusActive); err != nil {
			t.Fatal(err)
		}
		if err := g.Access.AssignRole(ctx, id, RoleSuperAdmin, "", nil); err != nil {
			t.Fatal(err)
		}
	}
}

// runPair starts a and b together and returns their errors.
func runPair(a, b func() error) (error, error) {
	var ea, eb error
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(2)
	go func() { defer wg.Done(); <-start; ea = a() }()
	go func() { defer wg.Done(); <-start; eb = b() }()
	close(start)
	wg.Wait()
	return ea, eb
}

func TestSuperAdminRacePostgres(t *testing.T) {
	g1, g2 := raceGuards(t)
	ctx := context.Background()
	ban := identitydomain.StatusBanned
	scenarios := map[string]func() (error, error){
		"ban each other": func() (error, error) {
			return runPair(func() error { return g1.SetUserStatus(ctx, "1", "2", ban) },
				func() error { return g2.SetUserStatus(ctx, "2", "1", ban) })
		},
		"ban A + remove B role": func() (error, error) {
			return runPair(func() error { return g1.SetUserStatus(ctx, "2", "1", identitydomain.StatusSuspended) },
				func() error { return g2.UnassignRole(ctx, "2", "2", RoleSuperAdmin) })
		},
		"ban A + remove B role via Access": func() (error, error) {
			return runPair(func() error { return g1.SetUserStatus(ctx, "2", "1", ban) },
				func() error { return g2.Access.UnassignRoleAs(ctx, "2", "2", RoleSuperAdmin) })
		},
		"remove each other": func() (error, error) {
			return runPair(func() error { return g1.UnassignRole(ctx, "1", "2", RoleSuperAdmin) },
				func() error { return g2.UnassignRole(ctx, "2", "1", RoleSuperAdmin) })
		},
	}
	for name, run := range scenarios {
		t.Run(name, func(t *testing.T) {
			for i := 0; i < 25; i++ {
				resetSuperAdmins(t, g1)
				ea, eb := run()
				if n := activeSuperAdmins(t, g1); n < 1 {
					ids, _ := g1.SuperAdmins(ctx)
					u1, _ := g1.Identity.User(ctx, "1")
					u2, _ := g1.Identity.User(ctx, "2")
					t.Fatalf("iteration %d: no active super admin left (errs %v / %v) holders=%v s1=%s s2=%s", i, ea, eb, ids, u1.Status, u2.Status)
				}
				// Exactly one side wins; the loser gets ErrLastSuperAdmin.
				if (ea == nil) == (eb == nil) {
					t.Fatalf("iteration %d: errs %v / %v", i, ea, eb)
				}
				if lost := errors.Join(ea, eb); !errors.Is(lost, accessdomain.ErrLastSuperAdmin) && !errors.Is(lost, accessdomain.ErrForbidden) {
					t.Fatalf("iteration %d: loser error %v", i, lost)
				}
			}
		})
	}
}

func TestSuperAdminRaceMemory(t *testing.T) {
	e := newSuperEnv(t, false)
	e.g.Sessions = sessionapp.NewService(sessioninfra.NewRedisSessions(redis.NewClient(&redis.Options{Addr: miniredis.RunT(t).Addr()}), ""), sessionPolicy(SessionPolicy{}))
	ctx := context.Background()
	for _, id := range []string{"1", "2"} {
		if _, err := e.g.EnsureSuperAdmin(ctx, id, "sa"+id+"@example.com", saPW); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 50; i++ {
		resetSuperAdmins(t, e.g)
		ea, eb := runPair(func() error { return e.g.SetUserStatus(ctx, "2", "1", identitydomain.StatusBanned) },
			func() error { return e.g.UnassignRole(ctx, "2", "2", RoleSuperAdmin) })
		if activeSuperAdmins(t, e.g) < 1 || (ea == nil) == (eb == nil) {
			t.Fatalf("iteration %d: errs %v / %v", i, ea, eb)
		}
	}
	// Role removal ignores a banned co-holder.
	resetSuperAdmins(t, e.g)
	if err := e.g.SetUserStatus(ctx, "1", "2", identitydomain.StatusBanned); err != nil {
		t.Fatal(err)
	}
	if err := e.g.UnassignRole(ctx, "1", "1", RoleSuperAdmin); !errors.Is(err, ErrLastSuperAdmin) {
		t.Fatal(err)
	}
	// Unblocking never takes the lock path's check and always succeeds.
	if err := e.g.SetUserStatus(ctx, "1", "2", identitydomain.StatusActive); err != nil {
		t.Fatal(err)
	}
}
