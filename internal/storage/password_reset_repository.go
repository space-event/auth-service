package storage

import (
	"context"
	"errors"
	"github.com/space-event/auth-service/internal/model"

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
	_, err := r.db.Exec(ctx, `INSERT INTO password_reset_tokens (id, email, token_hash, 
		expires_at, created_at) VALUES ($1, $2, $3, $4, $5)`, params.ID, params.Email,
		params.TokenHash, params.ExpiresAt, params.CreatedAt)

	return err
}

func (r *PasswordResetRepository) GetByToken(ctx context.Context,
	tokenHash string) (*model.ResetPassword, error) {
	var data model.ResetPassword
	err := r.db.QueryRow(ctx, `SELECT id, email, token_hash, expires_at, 
		created_at FROM password_reset_tokens WHERE token_hash = $1`, tokenHash).Scan(&data.ID,
		&data.Email, &data.TokenHash, &data.ExpiresAt, &data.CreatedAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrorTokenNotFount
		}
		return nil, err
	}

	return &data, nil
}
