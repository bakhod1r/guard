package infrastructure

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/bakhod1r/guard/session/domain"
)

var _ domain.Taker = (*RedisSessions)(nil)

func TestTakeIsAtomicGetAndDelete(t *testing.T) {
	mr, _, r := setup(t)
	ctx := context.Background()
	s := sess("u")
	if err := r.Save(ctx, s, time.Minute); err != nil {
		t.Fatal(err)
	}
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		wins int
	)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got, err := r.Take(ctx, s.ID); err == nil && got.ID == s.ID {
				mu.Lock()
				wins++
				mu.Unlock()
			} else if !errors.Is(err, domain.ErrSessionNotFound) {
				t.Errorf("take: %v", err)
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("winners: %d", wins)
	}
	if mr.Exists("t:session:" + string(s.ID)) {
		t.Fatal("session key left")
	}
	if ok, _ := mr.SIsMember("t:user_sessions:u", string(s.ID)); ok {
		t.Fatal("id left in user set")
	}
}

func TestTakeErrors(t *testing.T) {
	mr, _, r := setup(t)
	ctx := context.Background()
	_ = mr.Set("t:session:bad", "{not json")
	if _, err := r.Take(ctx, "bad"); err == nil || errors.Is(err, domain.ErrSessionNotFound) {
		t.Fatalf("corrupt: %v", err)
	}
	if mr.Exists("t:session:bad") {
		t.Fatal("corrupt value must be consumed")
	}

	_, rdb2, r2 := setup(t)
	_ = rdb2.Close()
	if _, err := r2.Take(ctx, "x"); !errors.Is(err, redis.ErrClosed) {
		t.Fatalf("closed: %v", err)
	}
}

func TestSaveLimitedDropsCorruptSessions(t *testing.T) {
	mr, _, r := setup(t)
	ctx := context.Background()
	_, _ = mr.SAdd("t:user_sessions:u", "bad")
	_ = mr.Set("t:session:bad", "{not json")
	s := sess("u")
	if err := r.SaveLimited(ctx, s, time.Minute, 2); err != nil {
		t.Fatalf("corrupt session must not block login: %v", err)
	}
	if mr.Exists("t:session:bad") {
		t.Fatal("corrupt session not deleted")
	}
	members, _ := mr.Members("t:user_sessions:u")
	if len(members) != 1 || members[0] != string(s.ID) {
		t.Fatalf("members: %v", members)
	}
}
