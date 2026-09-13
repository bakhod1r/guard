package infrastructure

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bakhod1r/guard/identity/domain"
)

const (
	pgUniqueViolation     = "23505"
	pgForeignKeyViolation = "23503"
	pgInvalidTextRepr     = "22P02"
	accountPKey           = "guard_account_pkey"
)

// PostgresUsers stores credentials in guard_account; the user row itself is host-owned.
type PostgresUsers struct{ db *pgxpool.Pool }

func NewPostgresUsers(db *pgxpool.Pool) *PostgresUsers { return &PostgresUsers{db: db} }

func pgCode(err error) (*pgconn.PgError, bool) {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr, true
	}
	return nil, false
}

func (r *PostgresUsers) Create(ctx context.Context, u *domain.User) error {
	attrs, err := json.Marshal(u.Attributes)
	if err != nil {
		return err
	}
	_, err = r.db.Exec(ctx, `INSERT INTO guard_account
		(user_id, email, secret, status, attributes, failed_attempts, last_failed_at, last_login_at, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		string(u.ID), string(u.Email), u.PasswordHash, string(u.Status), attrs,
		u.FailedAttempts, u.LastFailedAt, u.LastLoginAt, u.CreatedAt, u.UpdatedAt)
	if pgErr, ok := pgCode(err); ok {
		switch pgErr.Code {
		case pgUniqueViolation:
			if pgErr.ConstraintName == accountPKey {
				return domain.ErrAccountExists
			}
			return domain.ErrEmailTaken
		case pgForeignKeyViolation, pgInvalidTextRepr:
			return domain.ErrUserNotFound
		}
	}
	return err
}

func (r *PostgresUsers) Update(ctx context.Context, u *domain.User) error {
	attrs, err := json.Marshal(u.Attributes)
	if err != nil {
		return err
	}
	tag, err := r.db.Exec(ctx, `UPDATE guard_account SET email=$2, secret=$3, status=$4, attributes=$5,
		failed_attempts=$6, last_failed_at=$7, last_login_at=$8, updated_at=$9 WHERE user_id=$1`,
		string(u.ID), string(u.Email), u.PasswordHash, string(u.Status), attrs,
		u.FailedAttempts, u.LastFailedAt, u.LastLoginAt, u.UpdatedAt)
	if pgErr, ok := pgCode(err); ok {
		switch pgErr.Code {
		case pgUniqueViolation:
			return domain.ErrEmailTaken
		case pgInvalidTextRepr:
			return domain.ErrUserNotFound
		}
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}

const selectAccount = `SELECT user_id::text, email, status, attributes, last_login_at, created_at, updated_at,
	secret, failed_attempts, last_failed_at FROM guard_account`

func (r *PostgresUsers) ByID(ctx context.Context, id domain.UserID) (*domain.User, error) {
	return r.one(ctx, selectAccount+` WHERE user_id = $1`, string(id))
}

func (r *PostgresUsers) ByEmail(ctx context.Context, email domain.Email) (*domain.User, error) {
	return r.one(ctx, selectAccount+` WHERE email = $1`, string(email))
}

func (r *PostgresUsers) one(ctx context.Context, q string, arg any) (*domain.User, error) {
	var u domain.User
	var id, email, status string
	var attrs []byte
	err := r.db.QueryRow(ctx, q, arg).Scan(&id, &email, &status, &attrs, &u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt,
		&u.PasswordHash, &u.FailedAttempts, &u.LastFailedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrUserNotFound
	}
	if pgErr, ok := pgCode(err); ok && pgErr.Code == pgInvalidTextRepr {
		return nil, domain.ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	u.ID, u.Email, u.Status = domain.UserID(id), domain.Email(email), domain.Status(status)
	if err := json.Unmarshal(attrs, &u.Attributes); err != nil {
		return nil, err
	}
	return &u, nil
}
