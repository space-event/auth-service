package storage

import (
	"context"
	"errors"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/space-event/auth-service/internal/logger"
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
	start := time.Now()

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	logger.Debug("Creating refresh token",
		"layer", "db",
		"user_id", refreshToken.UserID,
		"token_prefix", refreshToken.Token[:8],
		"expires_at", refreshToken.ExpiresAt,
	)

	builder := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	query, args, err := builder.Insert("refresh_tokens").
		Columns("id", "token", "expires_at", "is_revoked", "user_id", "created_at").
		Values(refreshToken.ID, refreshToken.Token, refreshToken.ExpiresAt, refreshToken.IsRevoked, refreshToken.UserID, refreshToken.CreatedAt).ToSql()

	if err != nil {
		logger.Error("Failed to build refresh token insert query",
			"layer", "db",
			"error", err.Error(),
			"user_id", refreshToken.UserID,
		)
		return err
	}

	_, err = r.db.Exec(ctx, query, args...)
	if err != nil {
		logger.Error("Failed to create refresh token",
			"layer", "db",
			"error", err.Error(),
			"user_id", refreshToken.UserID,
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return err
	}

	logger.Debug("Refresh token created successfully",
		"layer", "db",
		"user_id", refreshToken.UserID,
		"duration_ms", time.Since(start).Milliseconds(),
	)

	return nil
}

func (r *RefreshTokenRepository) GetByToken(ctx context.Context, tokenString string) (*model.RefreshToken, error) {
	start := time.Now()

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	logger.Debug("Fetching refresh token by token",
		"layer", "db",
		"token_prefix", tokenString[:8],
	)

	builder := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	query, args, err := builder.Select().
		Columns("id", "token", "expires_at", "is_revoked", "user_id", "created_at").
		From("refresh_tokens").Where(sq.Eq{"token": tokenString}).ToSql()

	if err != nil {
		logger.Error("Failed to build select query",
			"layer", "db",
			"error", err.Error(),
			"token_prefix", tokenString[:8],
		)
		return nil, err
	}

	var refreshToken model.RefreshToken

	err = r.db.QueryRow(ctx, query, args...).Scan(&refreshToken.ID,
		&refreshToken.Token, &refreshToken.ExpiresAt, &refreshToken.IsRevoked,
		&refreshToken.UserID, &refreshToken.CreatedAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			logger.Warn("Refresh token not found",
				"layer", "db",
				"token_prefix", tokenString[:8],
				"duration_ms", time.Since(start).Milliseconds(),
			)
			return nil, ErrTokenNotFound
		}

		logger.Error("Failed to get refresh token",
			"layer", "db",
			"error", err.Error(),
			"token_prefix", tokenString[:8],
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return nil, err
	}

	logger.Debug("Refresh token found",
		"layer", "db",
		"user_id", refreshToken.UserID,
		"is_revoked", refreshToken.IsRevoked,
		"expires_at", refreshToken.ExpiresAt,
		"duration_ms", time.Since(start).Milliseconds(),
	)

	return &refreshToken, nil
}

func (r *RefreshTokenRepository) Revoke(ctx context.Context, tokenString string) error {
	start := time.Now()

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	logger.Debug("Revoking refresh token",
		"layer", "db",
		"token_prefix", tokenString[:8],
	)

	builder := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	query, args, err := builder.Update("refresh_tokens").
		Set("is_revoked", true).
		Where(sq.Eq{
			"token":      tokenString,
			"is_revoked": false,
		}).ToSql()

	if err != nil {
		logger.Error("Failed to build revoke query",
			"layer", "db",
			"error", err.Error(),
			"token_prefix", tokenString[:8],
		)
		return err
	}

	result, err := r.db.Exec(ctx, query, args...)
	if err != nil {
		logger.Error("Failed to revoke refresh token",
			"layer", "db",
			"error", err.Error(),
			"token_prefix", tokenString[:8],
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return err
	}

	if result.RowsAffected() == 0 {
		logger.Warn("Refresh token not found or already revoked",
			"layer", "db",
			"token_prefix", tokenString[:8],
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return ErrTokenNotFound
	}

	logger.Debug("Refresh token revoked successfully",
		"layer", "db",
		"token_prefix", tokenString[:8],
		"duration_ms", time.Since(start).Milliseconds(),
	)

	return nil
}

func (r *RefreshTokenRepository) RevokeAllUsersTokens(ctx context.Context, userID string) error {
	start := time.Now()

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	logger.Debug("Revoking all tokens for user",
		"layer", "db",
		"user_id", userID,
	)

	builder := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	query, args, err := builder.Update("refresh_tokens").
		Set("is_revoked", true).
		Where(sq.Eq{
			"user_id": userID,
		}).ToSql()

	if err != nil {
		logger.Error("Failed to build revoke all query",
			"layer", "db",
			"error", err.Error(),
			"user_id", userID,
		)
		return err
	}

	result, err := r.db.Exec(ctx, query, args...)
	if err != nil {
		logger.Error("Failed to revoke all user tokens",
			"layer", "db",
			"error", err.Error(),
			"user_id", userID,
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return err
	}

	logger.Info("All refresh tokens revoked for user",
		"layer", "db",
		"user_id", userID,
		"rows_affected", result.RowsAffected(),
		"duration_ms", time.Since(start).Milliseconds(),
	)

	return nil
}

func (r *RefreshTokenRepository) DeleteExpired(ctx context.Context) error {
	start := time.Now()

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	logger.Debug("Deleting expired refresh tokens",
		"layer", "db",
	)

	builder := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	query, args, err := builder.Delete("refresh_tokens").
		Where(sq.Lt{
			"expires_at": time.Now(),
		}).ToSql()

	if err != nil {
		logger.Error("Failed to build delete expired query",
			"layer", "db",
			"error", err.Error(),
		)
		return err
	}

	result, err := r.db.Exec(ctx, query, args...)
	if err != nil {
		logger.Error("Failed to delete expired refresh tokens",
			"layer", "db",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return err
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected > 0 {
		logger.Info("Deleted expired refresh tokens",
			"layer", "db",
			"rows_affected", rowsAffected,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	} else {
		logger.Debug("No expired refresh tokens to delete",
			"layer", "db",
			"duration_ms", time.Since(start).Milliseconds(),
		)
	}

	return nil
}
