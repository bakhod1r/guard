package domain

import (
	_ "embed"
	"strings"
)

// commonPasswordsFile holds ~1000 of the most frequent leaked passwords of
// length >= 8, lowercased (SecLists 10k-most-common, filtered).
//
//go:embed common_passwords.txt
var commonPasswordsFile string

var commonPasswords = func() map[string]struct{} {
	m := make(map[string]struct{}, 1024)
	for _, w := range strings.Fields(commonPasswordsFile) {
		m[w] = struct{}{}
	}
	return m
}()

// policyError is a password-policy rejection that also matches ErrWeakPassword.
type policyError string

func (e policyError) Error() string        { return string(e) }
func (e policyError) Is(target error) bool { return target == ErrWeakPassword }

var (
	ErrCommonPassword       error = policyError("identity: password is too common")
	ErrPasswordMatchesEmail error = policyError("identity: password must not match the email")
)

// ValidatePasswordFor applies ValidatePassword plus account-aware rules: the
// password must not equal the email local part nor be a common password.
// Comparisons are case-insensitive.
func ValidatePasswordFor(email, plain string) error {
	if err := ValidatePassword(plain); err != nil {
		return err
	}
	lower := strings.ToLower(plain)
	if local, _, ok := strings.Cut(email, "@"); ok && strings.ToLower(local) == lower {
		return ErrPasswordMatchesEmail
	}
	if _, bad := commonPasswords[lower]; bad {
		return ErrCommonPassword
	}
	return nil
}
