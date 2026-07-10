package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/space-event/auth-service/internal/infrastructure"
	"github.com/space-event/auth-service/internal/model"
	"github.com/space-event/auth-service/internal/storage"
	"github.com/space-event/auth-service/pkg/dto"

	"github.com/google/uuid"
)

var (
	ErrUserAlreadyExists = errors.New("user already exists")
	ErrInvalidEmail      = errors.New("invalid email")
	ErrWeakPassword      = errors.New("weak password")
	ErrSomethingWrong    = errors.New("something went wrong")
	ErrorTokenExpires    = errors.New("token has expired")
)

type AuthService struct {
	hasher            *infrastructure.BcryptHasher
	tokensRepo        *storage.RefreshTokenRepository
	resetPasswordRepo *storage.PasswordResetRepository
	userRepo          *storage.UserRepository
	jwt               *infrastructure.JWTService
}

func NewAuthService(hasher *infrastructure.BcryptHasher, resetPasswordRepo *storage.PasswordResetRepository, tokensRepo *storage.RefreshTokenRepository, userRepo *storage.UserRepository, jwt *infrastructure.JWTService) *AuthService {
	return &AuthService{hasher: hasher, resetPasswordRepo: resetPasswordRepo, tokensRepo: tokensRepo, userRepo: userRepo, jwt: jwt}
}

func (s *AuthService) GenerateToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (s *AuthService) Register(ctx context.Context, request dto.RegisterRequest) (*dto.TokenResponse, error) {

	if request.Email == "" {
		return nil, ErrInvalidEmail
	}

	if utf8.RuneCountInString(request.Password) < 6 {
		return nil, ErrWeakPassword
	}

	exists, err := s.userRepo.Exists(ctx, request.Email)

	if err != nil {
		return nil, err
	}
	if exists {
		return nil, ErrUserAlreadyExists
	}

	hash, err := s.hasher.Hash(request.Password)
	if err != nil {
		return nil, err
	}

	user := &model.User{
		ID:           uuid.NewString(),
		Email:        request.Email,
		PasswordHash: hash,
		CreatedAt:    time.Now().UTC(),
		Firstname:    request.Firstname,
		Lastname:     request.Lastname,
	}

	if err = s.userRepo.Create(ctx, user); err != nil {
		return nil, err
	}

	tokens, err := s.jwt.Generate(user.ID, request.Email)

	if err != nil {
		return nil, err
	}

	rt := &model.RefreshToken{
		ID:        uuid.NewString(),
		UserID:    user.ID,
		Token:     tokens.RefreshToken,
		ExpiresAt: time.Now().UTC().Add(s.jwt.RefreshTokenTTL),
		CreatedAt: time.Now().UTC(),
		IsRevoked: false,
	}

	if err = s.tokensRepo.Create(ctx, rt); err != nil {
		return nil, err
	}

	return &dto.TokenResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresAt:    tokens.ExpiresAt,
	}, nil
}

func (s *AuthService) Login(ctx context.Context, request dto.LoginRequest) (*dto.TokenResponse, error) {

	user, err := s.userRepo.GetByEmail(ctx, request.Email)

	if err != nil {
		return nil, errors.New("invalid credentials")
	}

	if err = s.hasher.Verify(request.Password, user.PasswordHash); err != nil {
		return nil, errors.New("invalid credentials")
	}

	tokens, err := s.jwt.Generate(user.ID, user.Email)

	if err != nil {
		return nil, err
	}

	refreshToken := &model.RefreshToken{
		ID:        uuid.NewString(),
		Token:     tokens.RefreshToken,
		ExpiresAt: time.Now().UTC().Add(s.jwt.RefreshTokenTTL),
		CreatedAt: time.Now().UTC(),
		UserID:    user.ID,
		IsRevoked: false,
	}

	if err = s.tokensRepo.Create(ctx, refreshToken); err != nil {
		return nil, err
	}

	return &dto.TokenResponse{AccessToken: tokens.AccessToken, RefreshToken: tokens.RefreshToken,
		ExpiresAt: tokens.ExpiresAt}, nil

}

func (s *AuthService) VerifyEmail(ctx context.Context, email string) error {
	exist, err := s.userRepo.Exists(ctx, email)
	if err != nil {
		return err
	}

	if !exist {
		return ErrInvalidEmail
	}

	return nil
}

func (s *AuthService) HashToken(ctx context.Context, token string) (string, error) {
	return s.hasher.Hash(token)
}

func (s *AuthService) SaveHashToken(ctx context.Context, email string, tokenHash string) error {
	params := &model.ResetPassword{
		ID:        uuid.NewString(),
		Email:     email,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().UTC().Add(time.Minute * 15),
		CreatedAt: time.Now().UTC(),
	}

	return s.resetPasswordRepo.Create(ctx, params)
}

func (s *AuthService) ResetPassword(ctx context.Context, token string, newPassword string) error {

	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])

	now := time.Now().UTC()

	data, err := s.resetPasswordRepo.GetByToken(ctx, tokenHash)

	if err != nil {
		return err
	}

	if data.ExpiresAt.Before(now) {
		return ErrorTokenExpires
	}

	passwordHash, err := s.hasher.Hash(newPassword)

	if err != nil {
		return ErrSomethingWrong
	}

	err = s.userRepo.UpdatePassword(ctx, data.Email, passwordHash)

	if err != nil {
		return err
	}

	return nil
}

func (s *AuthService) RefreshAccessToken(ctx context.Context,
	token string) (*dto.TokenPair, error) {

	refreshToken, err := s.tokensRepo.GetByToken(ctx, token)

	if err != nil {
		return nil, err
	}

	if refreshToken.IsRevoked {
		return nil, errors.New("refresh token revoked")
	}

	if time.Now().UTC().After(refreshToken.ExpiresAt) {
		return nil, errors.New("refresh token expired")
	}

	user, err := s.userRepo.GetByID(ctx, refreshToken.UserID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	if err = s.tokensRepo.Revoke(ctx, refreshToken.Token); err != nil {
		return nil, err
	}

	newTokens, err := s.jwt.Generate(user.ID, user.Email)

	if err != nil {
		return nil, err
	}

	newRefreshToken := &model.RefreshToken{
		ID:        uuid.NewString(),
		Token:     newTokens.RefreshToken,
		ExpiresAt: time.Now().UTC().Add(s.jwt.RefreshTokenTTL),
		IsRevoked: false,
		UserID:    user.ID,
		CreatedAt: time.Now().UTC(),
	}

	if err = s.tokensRepo.Create(ctx, newRefreshToken); err != nil {
		return nil, err
	}

	return newTokens, nil
}
