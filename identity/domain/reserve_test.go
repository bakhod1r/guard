package domain

import (
	"testing"
	"time"
)

func TestReserveAttemptCountsUntilLocked(t *testing.T) {
	l := Lockout{MaxAttempts: 2, Duration: time.Minute}
	now := time.Now()
	u := &User{}
	for i := 1; i <= 2; i++ {
		if !u.ReserveAttempt(now, l) || u.FailedAttempts != i {
			t.Fatalf("attempt %d: reserved=false or count %d", i, u.FailedAttempts)
		}
	}
	if u.ReserveAttempt(now, l) || u.FailedAttempts != 2 {
		t.Fatalf("locked account reserved an attempt: %d", u.FailedAttempts)
	}
	if !u.ReserveAttempt(now.Add(time.Minute), l) || u.FailedAttempts != 1 {
		t.Fatalf("expired lock must restart the count, got %d", u.FailedAttempts)
	}
}
