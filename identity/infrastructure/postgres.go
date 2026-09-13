package infrastructure

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bakhod1r/guard/identity/domain"
)

type PostgresUsers struct{ db *pgxpool.Pool }

func NewPostgresUsers(db *pgxpool.Pool) *PostgresUsers { return &PostgresUsers{db: db} }

func (r *PostgresUsers) Create(ctx context.Context, u *domain.User) error {
	attrs, err := json.Marshal(u.Attributes)
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, r.db, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO guard_user (id, email, status, attributes, last_login_at, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			string(u.ID), string(u.Email), string(u.Status), attrs, u.LastLoginAt, u.CreatedAt, u.UpdatedAt)
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return domain.ErrEmailTaken
		}
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO guard_identity (user_id, kind, secret, failed_attempts, last_failed_at, created_at, updated_at)
			VALUES ($1,'password',$2,$3,$4,$5,$6)`,
			string(u.ID), u.PasswordHash, u.FailedAttempts, u.LastFailedAt, u.CreatedAt, u.UpdatedAt)
		return err
	})
}

func (r *PostgresUsers) Update(ctx context.Context, u *domain.User) error {
	attrs, err := json.Marshal(u.Attributes)
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, r.db, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE guard_user SET email=$2, status=$3, attributes=$4, last_login_at=$5, updated_at=$6 WHERE id=$1`,
			string(u.ID), string(u.Email), string(u.Status), attrs, u.LastLoginAt, u.UpdatedAt)
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return domain.ErrEmailTaken
		}
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return domain.ErrUserNotFound
		}
		_, err = tx.Exec(ctx, `UPDATE guard_identity SET secret=$2, failed_attempts=$3, last_failed_at=$4, updated_at=$5
			WHERE user_id=$1 AND kind='password'`,
			string(u.ID), u.PasswordHash, u.FailedAttempts, u.LastFailedAt, u.UpdatedAt)
		return err
	})
}

const selectUser = `SELECT u.id::text, u.email, u.status, u.attributes, u.last_login_at, u.created_at, u.updated_at,
	i.secret, i.failed_attempts, i.last_failed_at
	FROM guard_user u JOIN guard_identity i ON i.user_id = u.id AND i.kind = 'password'`

func (r *PostgresUsers) ByID(ctx context.Context, id domain.UserID) (*domain.User, error) {
	if _, err := uuid.Parse(string(id)); err != nil {
		return nil, domain.ErrUserNotFound
	}
	return r.one(ctx, selectUser+` WHERE u.id = $1`, string(id))
}

func (r *PostgresUsers) ByEmail(ctx context.Context, email domain.Email) (*domain.User, error) {
	return r.one(ctx, selectUser+` WHERE u.email = $1`, string(email))
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
	if err != nil {
		return nil, err
	}
	u.ID, u.Email, u.Status = domain.UserID(id), domain.Email(email), domain.Status(status)
	if err := json.Unmarshal(attrs, &u.Attributes); err != nil {
		return nil, err
	}
	return &u, nil
}
