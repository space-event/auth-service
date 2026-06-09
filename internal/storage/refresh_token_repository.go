package storage

import (
	"context"
	"errors"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/space-event/auth-service/internal/model"

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

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	builder := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	query, args, err := builder.Insert("refresh_tokens").
		Columns("id", "token", "expires_at", "is_revoked", "user_id", "created_at").
		Values(refreshToken.ID, refreshToken.Token, refreshToken.ExpiresAt, refreshToken.IsRevoked, refreshToken.UserID, refreshToken.CreatedAt).ToSql()

	if err != nil {
		return err
	}

	_, err = r.db.Exec(ctx, query, args...)

	return err
}

func (r *RefreshTokenRepository) GetByToken(ctx context.Context, tokenString string) (*model.RefreshToken, error) {

	var refreshToken model.RefreshToken

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	builder := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	query, args, err := builder.Select().
		Columns("id", "token", "expires_at", "is_revoked", "user_id", "created_at").
		From("refresh_tokens").Where(sq.Eq{"token": tokenString}).ToSql()

	if err != nil {
		return nil, err
	}

	err = r.db.QueryRow(ctx, query, args...).Scan(&refreshToken.ID,
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

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	builder := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	query, args, err := builder.Update("refresh_tokens").
		Set("is_revoked", true).
		Where(sq.Eq{
			"token":      tokenString,
			"is_revoked": false,
		}).ToSql()

	if err != nil {
		return err
	}

	result, err := r.db.Exec(ctx, query, args...)

	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return ErrTokenNotFound
	}

	return nil
}

func (r *RefreshTokenRepository) RevokeAllUsersTokens(ctx context.Context, userID string) error {

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	builder := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	query, args, err := builder.Update("refresh_tokens").
		Set("is_revoked", true).
		Where(sq.Eq{
			"user_id": userID,
		}).ToSql()

	if err != nil {
		return err
	}

	_, err = r.db.Exec(ctx, query, args...)

	return err
}

func (r *RefreshTokenRepository) DeleteExpired(ctx context.Context) error {

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	builder := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	query, args, err := builder.Delete("refresh_tokens").
		Where(sq.Lt{
			"expires_at": time.Now(),
		}).ToSql()

	if err != nil {
		return err
	}

	_, err = r.db.Exec(ctx, query, args...)

	return err
}
