package storage

import (
	"context"
	"errors"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/space-event/auth-service/internal/logger"
	"github.com/space-event/auth-service/internal/model"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrUserNotFound      = errors.New("user not found")
	ErrUserAlreadyExists = errors.New("user already exists")
)

type UserRepository struct {
	db *pgxpool.Pool
}

func NewUserRepository(db *pgxpool.Pool) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, user *model.User) error {
	start := time.Now()

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	logger.Debug("Creating user",
		"layer", "db",
		"email", user.Email,
		"firstname", user.Firstname,
		"lastname", user.Lastname,
	)

	builder := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	query, args, err := builder.Insert("users").
		Columns("id", "email", "firstname", "lastname", "password_hash", "created_at").
		Values(user.ID, user.Email, user.Firstname, user.Lastname, user.PasswordHash, user.CreatedAt).ToSql()

	if err != nil {
		logger.Error("Failed to build user insert query",
			"layer", "db",
			"error", err.Error(),
			"email", user.Email,
		)
		return err
	}

	_, err = r.db.Exec(ctx, query, args...)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			logger.Warn("User already exists",
				"layer", "db",
				"email", user.Email,
				"duration_ms", time.Since(start).Milliseconds(),
			)
			return ErrUserAlreadyExists
		}

		logger.Error("Failed to create user",
			"layer", "db",
			"error", err.Error(),
			"email", user.Email,
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return err
	}

	logger.Info("User created successfully",
		"layer", "db",
		"user_id", user.ID,
		"email", user.Email,
		"duration_ms", time.Since(start).Milliseconds(),
	)

	return nil
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	start := time.Now()

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	logger.Debug("Fetching user by email",
		"layer", "db",
		"email", email,
	)

	builder := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	query, args, err := builder.Select().
		Columns("id", "email", "firstname", "lastname", "password_hash", "created_at").
		From("users").
		Where(sq.Eq{
			"email": email,
		}).ToSql()

	if err != nil {
		logger.Error("Failed to build select query",
			"layer", "db",
			"error", err.Error(),
			"email", email,
		)
		return nil, err
	}

	var user model.User

	err = r.db.QueryRow(ctx, query, args...).
		Scan(&user.ID, &user.Email, &user.Firstname, &user.Lastname, &user.PasswordHash, &user.CreatedAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			logger.Warn("User not found by email",
				"layer", "db",
				"email", email,
				"duration_ms", time.Since(start).Milliseconds(),
			)
			return nil, ErrUserNotFound
		}

		logger.Error("Failed to get user by email",
			"layer", "db",
			"error", err.Error(),
			"email", email,
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return nil, err
	}

	logger.Debug("User found by email",
		"layer", "db",
		"user_id", user.ID,
		"email", user.Email,
		"duration_ms", time.Since(start).Milliseconds(),
	)

	return &user, nil
}

func (r *UserRepository) GetByID(ctx context.Context, userID string) (*model.User, error) {
	start := time.Now()

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	logger.Debug("Fetching user by ID",
		"layer", "db",
		"user_id", userID,
	)

	builder := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	query, args, err := builder.Select().
		Columns("id", "email", "firstname", "lastname", "password_hash", "created_at").
		From("users").
		Where(sq.Eq{
			"id": userID,
		}).ToSql()

	if err != nil {
		logger.Error("Failed to build select query",
			"layer", "db",
			"error", err.Error(),
			"user_id", userID,
		)
		return nil, err
	}

	var user model.User

	err = r.db.QueryRow(ctx, query, args...).
		Scan(&user.ID, &user.Email, &user.Firstname, &user.Lastname, &user.PasswordHash, &user.CreatedAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			logger.Warn("User not found by ID",
				"layer", "db",
				"user_id", userID,
				"duration_ms", time.Since(start).Milliseconds(),
			)
			return nil, ErrUserNotFound
		}

		logger.Error("Failed to get user by ID",
			"layer", "db",
			"error", err.Error(),
			"user_id", userID,
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return nil, err
	}

	logger.Debug("User found by ID",
		"layer", "db",
		"user_id", user.ID,
		"email", user.Email,
		"duration_ms", time.Since(start).Milliseconds(),
	)

	return &user, nil
}

func (r *UserRepository) Exists(ctx context.Context, email string) (bool, error) {
	start := time.Now()

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	logger.Debug("Checking user existence",
		"layer", "db",
		"email", email,
	)

	var exists bool

	err := r.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)`, email).Scan(&exists)
	if err != nil {
		logger.Error("Failed to check user existence",
			"layer", "db",
			"error", err.Error(),
			"email", email,
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return false, err
	}

	logger.Debug("User existence checked",
		"layer", "db",
		"email", email,
		"exists", exists,
		"duration_ms", time.Since(start).Milliseconds(),
	)

	return exists, nil
}

func (r *UserRepository) Delete(ctx context.Context, userID string) error {
	start := time.Now()

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	logger.Debug("Deleting user",
		"layer", "db",
		"user_id", userID,
	)

	builder := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	query, args, err := builder.Delete("users").
		Where(sq.Eq{
			"id": userID,
		}).ToSql()

	if err != nil {
		logger.Error("Failed to build delete query",
			"layer", "db",
			"error", err.Error(),
			"user_id", userID,
		)
		return err
	}

	result, err := r.db.Exec(ctx, query, args...)
	if err != nil {
		logger.Error("Failed to delete user",
			"layer", "db",
			"error", err.Error(),
			"user_id", userID,
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return err
	}

	if result.RowsAffected() == 0 {
		logger.Warn("User not found for deletion",
			"layer", "db",
			"user_id", userID,
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return ErrUserNotFound
	}

	logger.Info("User deleted successfully",
		"layer", "db",
		"user_id", userID,
		"duration_ms", time.Since(start).Milliseconds(),
	)

	return nil
}

func (r *UserRepository) UpdatePassword(ctx context.Context, email string, passwordHash string) error {
	start := time.Now()

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	logger.Debug("Updating user password",
		"layer", "db",
		"email", email,
	)

	builder := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	query, args, err := builder.Update("users").
		Set("password_hash", passwordHash).
		Where(sq.Eq{
			"email": email,
		}).ToSql()

	if err != nil {
		logger.Error("Failed to build update password query",
			"layer", "db",
			"error", err.Error(),
			"email", email,
		)
		return err
	}

	result, err := r.db.Exec(ctx, query, args...)
	if err != nil {
		logger.Error("Failed to update user password",
			"layer", "db",
			"error", err.Error(),
			"email", email,
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return err
	}

	if result.RowsAffected() == 0 {
		logger.Warn("User not found for password update",
			"layer", "db",
			"email", email,
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return ErrUserNotFound
	}

	logger.Info("User password updated successfully",
		"layer", "db",
		"email", email,
		"duration_ms", time.Since(start).Milliseconds(),
	)

	return nil
}
