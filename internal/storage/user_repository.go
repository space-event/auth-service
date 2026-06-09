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

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	builder := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	query, args, err := builder.Insert("users").
		Columns("id", "email", "firstname", "lastname", "password_hash", "created_at").
		Values(user.ID, user.Email, user.Firstname, user.Lastname, user.PasswordHash, user.CreatedAt).ToSql()

	if err != nil {
		return err
	}

	_, err = r.db.Exec(ctx, query, args...)

	return err
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	var user model.User

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	builder := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	query, args, err := builder.Select().
		Columns("id", "email", "firstname", "lastname", "password_hash", "created_at").
		From("users").
		Where(sq.Eq{
			"email": email,
		}).ToSql()

	if err != nil {
		return nil, err
	}

	err = r.db.QueryRow(ctx, query, args...).
		Scan(&user.ID, &user.Email, &user.Firstname, &user.Lastname, &user.PasswordHash, &user.CreatedAt)

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

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	builder := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	query, args, err := builder.Select().
		Columns("id", "email", "firstname", "lastname", "password_hash", "created_at").
		From("users").
		Where(sq.Eq{
			"id": userId,
		}).ToSql()

	if err != nil {
		return nil, err
	}

	err = r.db.QueryRow(ctx, query, args...).
		Scan(&user.ID, &user.Email, &user.Firstname, &user.Lastname, &user.PasswordHash, &user.CreatedAt)

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

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	err := r.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)`, email).Scan(&exists)

	return exists, err
}

func (r *UserRepository) Delete(ctx context.Context, userID string) error {

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	builder := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	query, args, err := builder.Delete("users").
		Where(sq.Eq{
			"id": userID,
		}).ToSql()

	if err != nil {
		return err
	}

	result, err := r.db.Exec(ctx, query, args...)

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

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	builder := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	query, args, err := builder.Update("users").
		Set("password_hash", passwordHash).
		Where(sq.Eq{
			"email": email,
		}).ToSql()

	if err != nil {
		return err
	}

	_, err = r.db.Exec(ctx, query, args...)

	return err
}
