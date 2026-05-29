package storage

import (
	"EventSpace/internal/auth/model"
	"context"
	"errors"

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
	_, err := r.db.Exec(ctx, `INSERT INTO users (id, email, firstname, lastname,password_hash, 
		created_at) VALUES ($1, $2, $3, $4, $5, $6)`, user.ID, user.Email,
		user.Firstname, user.Lastname, user.PasswordHash,
		user.CreatedAt)

	return err
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	var user model.User

	err := r.db.QueryRow(ctx, `SELECT id, email, password_hash, 
		created_at FROM users WHERE email = $1`, email).
		Scan(&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return &user, nil
}

func (r *UserRepository) GetByID(ctx context.Context, userId string) (*model.User, error) {
	var user model.User

	err := r.db.QueryRow(ctx, `SELECT id, email, password_hash, 
		created_at FROM users WHERE id = $1`, userId).
		Scan(&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return &user, nil
}

func (r *UserRepository) Exists(ctx context.Context, email string) (bool, error) {
	var exists bool

	err := r.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)`, email).Scan(&exists)

	return exists, err
}

func (r *UserRepository) Delete(ctx context.Context, userID string) error {
	result, err := r.db.Exec(ctx, "DELETE FROM users WHERE user_id = $1", userID)

	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return ErrUserNotFound
	}

	return nil
}

func (r *UserRepository) UpdatePassword(ctx context.Context, email string,
	passwordHash string) error {

	_, err := r.db.Exec(ctx,
		`UPDATE users SET password_hash = $1 WHERE email = $2`, passwordHash, email)

	return err
}
