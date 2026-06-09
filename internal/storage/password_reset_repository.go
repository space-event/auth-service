package storage

import (
	"context"
	"errors"
	"time"

	"github.com/space-event/auth-service/internal/model"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrorTokenNotFount = errors.New("token hash no found")
)

type PasswordResetRepository struct {
	db *pgxpool.Pool
}

func NewPasswordResetRepository(db *pgxpool.Pool) *PasswordResetRepository {
	return &PasswordResetRepository{db: db}
}

func (r *PasswordResetRepository) Create(ctx context.Context, params *model.ResetPassword) error {

	ctx, cancel := context.WithTimeout(ctx, time.Second * 5)
	defer cancel()

	builder := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	query, args, err := builder.Insert("password_reset_tokens").
		Columns("id", "email", "token_hash", "expires_at", "created_at").
		Values(params.ID, params.Email, params.TokenHash, params.ExpiresAt, params.CreatedAt).ToSql()

	if err != nil {
		return err
	}

	_, err = r.db.Exec(ctx, query, args...)

	return err
}

func (r *PasswordResetRepository) GetByToken(ctx context.Context,
	tokenHash string) (*model.ResetPassword, error) {
	var data model.ResetPassword

	ctx, cancel := context.WithTimeout(ctx, time.Second * 5)
	defer cancel()

	builder := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	query, args, err := builder.Select().
		Columns("id", "email", "token_hash", "expires_at", "created_at").
		From("password_reset_tokens").
		Where(sq.Eq{
			"token_hash": tokenHash,
		}).ToSql()

	if err != nil {
		return nil, err
	}

	err = r.db.QueryRow(ctx, query, args...).Scan(&data.ID,
		&data.Email, &data.TokenHash, &data.ExpiresAt, &data.CreatedAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrorTokenNotFount
		}
		return nil, err
	}

	return &data, nil
}
