package infrastructure

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

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

// lockWindowEnd is last_failed_at + Lockout.Duration ($4, seconds).
const lockWindowEnd = `last_failed_at + make_interval(secs => $4::float8)`

// ReserveAttempt mirrors domain.User.ReserveAttempt in one statement: the row
// lock serialises concurrent attempts and the WHERE is re-checked after it.
func (r *PostgresUsers) ReserveAttempt(ctx context.Context, id domain.UserID, now time.Time, l domain.Lockout) (bool, error) {
	var n int
	err := r.db.QueryRow(ctx, `UPDATE guard_account SET
		failed_attempts = CASE WHEN last_failed_at IS NOT NULL AND failed_attempts >= $3::int AND $2 >= `+lockWindowEnd+`
			THEN 1 ELSE failed_attempts + 1 END,
		last_failed_at = $2, updated_at = $2
		WHERE user_id = $1 AND NOT ($3::int > 0 AND failed_attempts >= $3::int AND last_failed_at IS NOT NULL AND $2 < `+lockWindowEnd+`)
		RETURNING failed_attempts`,
		string(id), now, l.MaxAttempts, l.Duration.Seconds()).Scan(&n)
	if errors.Is(err, pgx.ErrNoRows) || isInvalidText(err) {
		return false, nil
	}
	return err == nil, err
}

func (r *PostgresUsers) RecordLogin(ctx context.Context, id domain.UserID, now time.Time, verifiedHash, newHash string) error {
	tag, err := r.db.Exec(ctx, `UPDATE guard_account SET secret = $4, failed_attempts = 0, last_failed_at = NULL,
		last_login_at = $2, updated_at = $2
		WHERE user_id = $1 AND secret = $3 AND status NOT IN ('banned', 'suspended')`,
		string(id), now, verifiedHash, newHash)
	if isInvalidText(err) || (err == nil && tag.RowsAffected() == 0) {
		return domain.ErrInvalidCredentials
	}
	return err
}

func (r *PostgresUsers) SetSecret(ctx context.Context, id domain.UserID, oldHash, hash string, now time.Time) error {
	tag, err := r.db.Exec(ctx, `UPDATE guard_account SET secret = $3, failed_attempts = 0, last_failed_at = NULL, updated_at = $4
		WHERE user_id = $1 AND ($2 = '' OR secret = $2)`, string(id), oldHash, hash, now)
	if err == nil && tag.RowsAffected() == 0 && oldHash != "" {
		return domain.ErrInvalidCredentials
	}
	return rowsOrNotFound(tag, err)
}

func (r *PostgresUsers) SetStatus(ctx context.Context, id domain.UserID, status domain.Status, now time.Time) error {
	tag, err := r.db.Exec(ctx, `UPDATE guard_account SET status = $2, updated_at = $3 WHERE user_id = $1`,
		string(id), string(status), now)
	return rowsOrNotFound(tag, err)
}

func (r *PostgresUsers) SetAttributes(ctx context.Context, id domain.UserID, attrs map[string]any, now time.Time) error {
	b, err := json.Marshal(attrs)
	if err != nil {
		return err
	}
	tag, err := r.db.Exec(ctx, `UPDATE guard_account SET attributes = $2, updated_at = $3 WHERE user_id = $1`,
		string(id), b, now)
	return rowsOrNotFound(tag, err)
}

func isInvalidText(err error) bool {
	pgErr, ok := pgCode(err)
	return ok && pgErr.Code == pgInvalidTextRepr
}

// rowsOrNotFound maps a malformed id or an untouched row to ErrUserNotFound.
func rowsOrNotFound(tag pgconn.CommandTag, err error) error {
	if isInvalidText(err) || (err == nil && tag.RowsAffected() == 0) {
		return domain.ErrUserNotFound
	}
	return err
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
	u, err := scanAccount(r.db.QueryRow(ctx, q, arg))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrUserNotFound
	}
	if pgErr, ok := pgCode(err); ok && pgErr.Code == pgInvalidTextRepr {
		return nil, domain.ErrUserNotFound
	}
	return u, err
}

func scanAccount(row pgx.Row) (*domain.User, error) {
	var u domain.User
	var id, email, status string
	var attrs []byte
	if err := row.Scan(&id, &email, &status, &attrs, &u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt,
		&u.PasswordHash, &u.FailedAttempts, &u.LastFailedAt); err != nil {
		return nil, err
	}
	u.ID, u.Email, u.Status = domain.UserID(id), domain.Email(email), domain.Status(status)
	if err := json.Unmarshal(attrs, &u.Attributes); err != nil {
		return nil, err
	}
	return &u, nil
}

// escapeLike makes s a literal for ILIKE ... ESCAPE '\'.
func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

const listWhere = ` WHERE ($1 = '' OR email ILIKE '%' || $2 || '%' ESCAPE '\' OR user_id::text = $1)
	AND ($3 = '' OR status = $3)`

func (r *PostgresUsers) List(ctx context.Context, q domain.ListQuery) ([]domain.User, int, error) {
	args := []any{q.Search, escapeLike(q.Search), string(q.Status)}
	var total int
	if err := r.db.QueryRow(ctx, `SELECT count(*) FROM guard_account`+listWhere, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.db.Query(ctx, selectAccount+listWhere+` ORDER BY created_at DESC, user_id::text LIMIT $4 OFFSET $5`,
		append(args, q.Limit, q.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []domain.User{}
	for rows.Next() {
		u, err := scanAccount(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *u)
	}
	return out, total, rows.Err()
}
