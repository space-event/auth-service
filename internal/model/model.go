package model

import (
	"time"
)

type RefreshToken struct {
	ID        string    `db:"id"`
	Token     string    `db:"token"`
	ExpiresAt time.Time `db:"expires_at"`
	IsRevoked bool      `db:"is_revoked"`
	UserID    string    `db:"user_id"`
	CreatedAt time.Time `db:"created_at"`
}

type User struct {
	ID           string    `db:"id"`
	Email        string    `db:"email"`
	PasswordHash string    `db:"password_hash"`
	CreatedAt    time.Time `db:"created_at"`
	Firstname    string    `db:"firstname"`
	Lastname     string    `db:"lastname"`
}

type ResetPassword struct {
	ID        string    `db:"id"`
	Email     string    `db:"email"`
	TokenHash string    `db:"token_hash"`
	ExpiresAt time.Time `db:"expires_at"`
	CreatedAt time.Time `db:"created_at"`
}
