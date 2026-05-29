package storage

import (
	"context"
	"errors"
	"github.com/space-event/auth-service/internal/model"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrTokenNotFound = errors.New("refresh token not found")
)

type RefreshTokenRepository struct {
	db *pgxpool.Pool
}

func NewRefreshTokenRepository(db *pgxpool.Pool) *RefreshTokenRepository {
	return &RefreshTokenRepository{db: db}
}

func (r *RefreshTokenRepository) Create(ctx context.Context, refreshToken *model.RefreshToken) error {

	_, err := r.db.Exec(ctx, `INSERT INTO refresh_tokens (id, token, expires_at, is_revoked, 
		user_id, created_at) VALUES ($1, $2, $3, $4, $5, $6)`, refreshToken.ID,
		refreshToken.Token, refreshToken.ExpiresAt, refreshToken.IsRevoked, refreshToken.UserID,
		refreshToken.CreatedAt)

	return err
}

func (r *RefreshTokenRepository) GetByToken(ctx context.Context, tokenString string) (*model.RefreshToken, error) {

	var refreshToken model.RefreshToken

	err := r.db.QueryRow(ctx, `SELECT id, token, expires_at, is_revoked, user_id,
		created_at FROM refresh_tokens WHERE token=$1`, tokenString).Scan(&refreshToken.ID,
		&refreshToken.Token, &refreshToken.ExpiresAt, &refreshToken.IsRevoked,
		&refreshToken.UserID, &refreshToken.CreatedAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrTokenNotFound
		}
		return nil, err
	}

	return &refreshToken, nil
}

func (r *RefreshTokenRepository) Revoke(ctx context.Context, tokenString string) error {
	result, err := r.db.Exec(ctx,
		`UPDATE refresh_tokens SET is_revoked = true WHERE token=$1 AND is_revoked=false`, tokenString)

	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return ErrTokenNotFound
	}

	return nil
}

func (r *RefreshTokenRepository) RevokeAllUsersTokens(ctx context.Context, userID string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE refresh_tokens SET is_revoked = true WHERE user_id=$1 AND is_revoked=false`, userID)

	return err
}

func (r *RefreshTokenRepository) DeleteExpired(ctx context.Context) error {
	_, err := r.db.Exec(ctx, `DELETE FROM refresh_tokens WHERE expires_at < $1`, time.Now())

	return err
}
