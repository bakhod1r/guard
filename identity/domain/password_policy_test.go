package domain

import (
	"bufio"
	"errors"
	"strings"
	"testing"
)

func TestValidatePasswordForRejectsCommonAndEmailLocalPart(t *testing.T) {
	cases := []struct {
		email, plain string
		want         error
	}{
		{"a@b.uz", "short", ErrWeakPassword},
		{"a@b.uz", "password", ErrCommonPassword},
		{"a@b.uz", "PassWord123", ErrCommonPassword},
		{"a@b.uz", "12345678", ErrCommonPassword},
		{"Ali.Valiyev@b.uz", "ali.VALIYEV", ErrPasswordMatchesEmail},
		{"not-an-email", "not-an-email", nil},
		{"", "correct-horse-1", nil},
		{"a@b.uz", "correct-horse-1", nil},
	}
	for _, c := range cases {
		err := ValidatePasswordFor(c.email, c.plain)
		if c.want == nil && err != nil || c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%q/%q: got %v want %v", c.email, c.plain, err, c.want)
		}
		if c.want != nil && !errors.Is(err, ErrWeakPassword) {
			t.Errorf("%q: policy errors must match ErrWeakPassword", c.plain)
		}
	}
	if errors.Is(ErrCommonPassword, ErrUserNotFound) || ErrCommonPassword.Error() == ErrWeakPassword.Error() {
		t.Fatal("policy error identity")
	}
}

func TestCommonPasswordListShape(t *testing.T) {
	if len(commonPasswordsFile) >= 50_000 {
		t.Fatalf("list too big: %d", len(commonPasswordsFile))
	}
	n := 0
	sc := bufio.NewScanner(strings.NewReader(commonPasswordsFile))
	for sc.Scan() {
		w := sc.Text()
		if len(w) < MinPasswordLength || strings.ToLower(w) != w {
			t.Fatalf("bad entry %q", w)
		}
		n++
	}
	if n < 900 || len(commonPasswords) != n {
		t.Fatalf("entries=%d set=%d", n, len(commonPasswords))
	}
}
