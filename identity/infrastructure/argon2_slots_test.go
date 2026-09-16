package infrastructure

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestArgon2ConcurrencyIsBounded(t *testing.T) {
	h := &Argon2Hasher{Memory: 1024, Time: 1, Threads: 1, KeyLen: 16, SaltLen: 16}
	var cur, peak atomic.Int32
	var wg sync.WaitGroup
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				n := int32(len(hashSlots))
				cur.Store(n)
				if n > peak.Load() {
					peak.Store(n)
				}
			}
		}
	}()
	for range 4 * cap(hashSlots) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = h.Hash("password-123")
		}()
	}
	wg.Wait()
	close(stop)
	if int(peak.Load()) > cap(hashSlots) || len(hashSlots) != 0 {
		t.Fatalf("peak %d over %d slots, left %d", peak.Load(), cap(hashSlots), len(hashSlots))
	}
}
