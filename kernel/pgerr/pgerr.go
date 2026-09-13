// Package pgerr classifies PostgreSQL errors returned through pgx.
package pgerr

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

// SQLSTATE codes Guard reacts to.
const (
	CodeUniqueViolation     = "23505"
	CodeForeignKeyViolation = "23503"
	CodeNotNullViolation    = "23502"
	CodeInvalidText         = "22P02"
)

func code(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

// IsUniqueViolation reports SQLSTATE 23505.
func IsUniqueViolation(err error) bool { return code(err) == CodeUniqueViolation }

// IsForeignKeyViolation reports SQLSTATE 23503.
func IsForeignKeyViolation(err error) bool { return code(err) == CodeForeignKeyViolation }

// IsNotNullViolation reports SQLSTATE 23502.
func IsNotNullViolation(err error) bool { return code(err) == CodeNotNullViolation }

// IsInvalidText reports SQLSTATE 22P02 (invalid_text_representation), e.g. "abc" for a bigint or uuid column.
func IsInvalidText(err error) bool { return code(err) == CodeInvalidText }

// Constraint returns the violated constraint name, or "" when unavailable.
func Constraint(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.ConstraintName
	}
	return ""
}
