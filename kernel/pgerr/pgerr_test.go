package pgerr

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestClassify(t *testing.T) {
	wrap := func(code, constraint string) error {
		return fmt.Errorf("repo: %w", &pgconn.PgError{Code: code, ConstraintName: constraint})
	}
	cases := []struct {
		name                         string
		err                          error
		unique, fk, notNull, invalid bool
		constraint                   string
	}{
		{"nil", nil, false, false, false, false, ""},
		{"plain", errors.New("boom"), false, false, false, false, ""},
		{"unique", wrap("23505", "guard_role_name_key"), true, false, false, false, "guard_role_name_key"},
		{"fk", wrap("23503", "guard_user_role_user_id_fkey"), false, true, false, false, "guard_user_role_user_id_fkey"},
		{"notnull", wrap("23502", ""), false, false, true, false, ""},
		{"invalid", &pgconn.PgError{Code: "22P02"}, false, false, false, true, ""},
		{"other", wrap("40001", ""), false, false, false, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsUniqueViolation(c.err); got != c.unique {
				t.Errorf("IsUniqueViolation=%v", got)
			}
			if got := IsForeignKeyViolation(c.err); got != c.fk {
				t.Errorf("IsForeignKeyViolation=%v", got)
			}
			if got := IsNotNullViolation(c.err); got != c.notNull {
				t.Errorf("IsNotNullViolation=%v", got)
			}
			if got := IsInvalidText(c.err); got != c.invalid {
				t.Errorf("IsInvalidText=%v", got)
			}
			if got := Constraint(c.err); got != c.constraint {
				t.Errorf("Constraint=%q", got)
			}
		})
	}
}
