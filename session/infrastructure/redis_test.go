package infrastructure

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/bakhod1r/guard/session/application"
	"github.com/bakhod1r/guard/session/domain"
)

func TestRedisSessionLifecycle(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	ctx := context.Background()
	svc := application.NewService(NewRedisSessions(rdb, "t:"), domain.DefaultPolicy())

	s1, tok1, err := svc.Start(ctx, application.StartInput{UserID: "u1", IP: "1.2.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	_, tok2, _ := svc.Start(ctx, application.StartInput{UserID: "u1"})

	got, err := svc.Resolve(ctx, tok1)
	if err != nil || got.UserID != "u1" || got.IP != "1.2.3.4" {
		t.Fatalf("resolve: %+v %v", got, err)
	}
	if mr.Exists("t:session:" + string(tok1)) {
		t.Fatal("raw token must not be stored as key")
	}
	if list, _ := svc.List(ctx, "u1"); len(list) != 2 {
		t.Fatalf("want 2 sessions, got %d", len(list))
	}
	if err := svc.Revoke(ctx, s1.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Resolve(ctx, tok1); err != domain.ErrSessionNotFound {
		t.Fatalf("revoked session resolved: %v", err)
	}
	if err := svc.RevokeAll(ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Resolve(ctx, tok2); err != domain.ErrSessionNotFound {
		t.Fatal("revoke all failed")
	}
}

func TestRedisIdleExpiry(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	ctx := context.Background()
	svc := application.NewService(NewRedisSessions(rdb, ""), domain.Policy{IdleTimeout: time.Minute, AbsoluteTimeout: time.Hour})
	_, tok, _ := svc.Start(ctx, application.StartInput{UserID: "u"})
	mr.FastForward(61 * time.Second)
	if _, err := svc.Resolve(ctx, tok); err != domain.ErrSessionNotFound {
		t.Fatalf("idle session alive: %v", err)
	}
}
