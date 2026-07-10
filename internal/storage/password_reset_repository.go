package storage

import (
	"context"
	"errors"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/space-event/auth-service/internal/logger"
	"github.com/space-event/auth-service/internal/model"
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
	start := time.Now()

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	builder := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	query, args, err := builder.Insert("password_reset_tokens").
		Columns("id", "email", "token_hash", "expires_at", "created_at").
		Values(params.ID, params.Email, params.TokenHash, params.ExpiresAt, params.CreatedAt).ToSql()

	if err != nil {
		logger.Error("Failed to build insert query",
			"layer", "db",
			"error", err.Error(),
			"email", params.Email,
		)
		return err
	}

	logger.Debug("Creating password reset token",
		"layer", "db",
		"email", params.Email,
		"token_hash_prefix", params.TokenHash[:8],
	)

	_, err = r.db.Exec(ctx, query, args...)
	if err != nil {
		logger.Error("Failed to create password reset token",
			"layer", "db",
			"error", err.Error(),
			"email", params.Email,
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return err
	}

	logger.Debug("Password reset token created successfully",
		"layer", "db",
		"email", params.Email,
		"duration_ms", time.Since(start).Milliseconds(),
	)

	return nil
}

func (r *PasswordResetRepository) GetByToken(ctx context.Context, tokenHash string) (*model.ResetPassword, error) {
	start := time.Now()

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	builder := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	query, args, err := builder.Select().
		Columns("id", "email", "token_hash", "expires_at", "created_at").
		From("password_reset_tokens").
		Where(sq.Eq{
			"token_hash": tokenHash,
		}).ToSql()

	if err != nil {
		logger.Error("Failed to build select query",
			"layer", "db",
			"error", err.Error(),
			"token_hash_prefix", tokenHash[:8],
		)
		return nil, err
	}

	logger.Debug("Fetching password reset token by hash",
		"layer", "db",
		"token_hash_prefix", tokenHash[:8],
	)

	var data model.ResetPassword

	err = r.db.QueryRow(ctx, query, args...).Scan(&data.ID,
		&data.Email, &data.TokenHash, &data.ExpiresAt, &data.CreatedAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			logger.Warn("Password reset token not found",
				"layer", "db",
				"token_hash_prefix", tokenHash[:8],
				"duration_ms", time.Since(start).Milliseconds(),
			)
			return nil, ErrorTokenNotFount
		}

		logger.Error("Failed to get password reset token",
			"layer", "db",
			"error", err.Error(),
			"token_hash_prefix", tokenHash[:8],
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return nil, err
	}

	logger.Debug("Password reset token found",
		"layer", "db",
		"email", data.Email,
		"expires_at", data.ExpiresAt,
		"duration_ms", time.Since(start).Milliseconds(),
	)

	return &data, nil
}
