package storage

import (
	"testing"
	"time"

	"github.com/go-playground/assert/v2"
	"github.com/google/uuid"
	"github.com/space-event/auth-service/internal/logger"
	"github.com/space-event/auth-service/internal/model"
	"github.com/space-event/auth-service/internal/storage"
	"github.com/stretchr/testify/require"
)

func TestRefreshTokenRepository_Create_And_GetByToken(t *testing.T) {
	logger.Init(LogLevel)

	testDb := SetupTestDb(t)
	defer testDb.TearDown()

	refreshRepo := storage.NewRefreshTokenRepository(testDb.Pool)

	params := &model.RefreshToken{
		ID:        uuid.NewString(),
		Token:     uuid.NewString(),
		ExpiresAt: time.Now().Add(5 * time.Minute).UTC(),
		IsRevoked: false,
		UserID:    uuid.NewString(),
		CreatedAt: time.Now(),
	}

	err := refreshRepo.Create(t.Context(), params)
	require.NoError(t, err)

	result, err := refreshRepo.GetByToken(t.Context(), params.Token)
	require.NoError(t, err)
	assert.Equal(t, params.ID, result.ID)
	assert.Equal(t, params.Token, result.Token)
	assert.Equal(t, params.ExpiresAt.UTC(), result.ExpiresAt.UTC())
	assert.Equal(t, params.IsRevoked, result.IsRevoked)
	assert.Equal(t, params.UserID, result.UserID)
	assert.Equal(t, params.CreatedAt.UTC(), result.CreatedAt.UTC())
}

func TestRefreshTokenRepository_Create_DuplicateUserID(t *testing.T) {
	logger.Init(LogLevel)

	testDb := SetupTestDb(t)
	defer testDb.TearDown()

	refreshRepo := storage.NewRefreshTokenRepository(testDb.Pool)

	userID := uuid.NewString()

	params1 := &model.RefreshToken{
		ID:        uuid.NewString(),
		Token:     uuid.NewString(),
		ExpiresAt: time.Now().Add(5 * time.Minute).UTC(),
		IsRevoked: false,
		UserID:    userID,
		CreatedAt: time.Now(),
	}

	params2 := &model.RefreshToken{
		ID:        uuid.NewString(),
		Token:     uuid.NewString(),
		ExpiresAt: time.Now().Add(5 * time.Minute).UTC(),
		IsRevoked: false,
		UserID:    userID,
		CreatedAt: time.Now(),
	}

	err := refreshRepo.Create(t.Context(), params1)
	require.NoError(t, err)

	err = refreshRepo.Create(t.Context(), params2)
	require.NoError(t, err)

}

func TestRefreshTokenRepository_Create_DuplicateToken(t *testing.T) {
	logger.Init(LogLevel)

	testDb := SetupTestDb(t)
	defer testDb.TearDown()

	refreshRepo := storage.NewRefreshTokenRepository(testDb.Pool)

	token := uuid.NewString()

	params1 := &model.RefreshToken{
		ID:        uuid.NewString(),
		Token:     token,
		ExpiresAt: time.Now().Add(5 * time.Minute).UTC(),
		IsRevoked: false,
		UserID:    uuid.NewString(),
		CreatedAt: time.Now(),
	}

	params2 := &model.RefreshToken{
		ID:        uuid.NewString(),
		Token:     token,
		ExpiresAt: time.Now().Add(5 * time.Minute).UTC(),
		IsRevoked: false,
		UserID:    uuid.NewString(),
		CreatedAt: time.Now(),
	}

	err := refreshRepo.Create(t.Context(), params1)
	require.NoError(t, err)

	err = refreshRepo.Create(t.Context(), params2)
	require.Error(t, err)

}

func TestRefreshTokenRepository_Revoke(t *testing.T) {
	logger.Init(LogLevel)

	testDb := SetupTestDb(t)
	defer testDb.TearDown()

	refreshRepo := storage.NewRefreshTokenRepository(testDb.Pool)

	params := &model.RefreshToken{
		ID:        uuid.NewString(),
		Token:     uuid.NewString(),
		ExpiresAt: time.Now().Add(5 * time.Minute).UTC(),
		IsRevoked: false,
		UserID:    uuid.NewString(),
		CreatedAt: time.Now(),
	}

	err := refreshRepo.Create(t.Context(), params)
	require.NoError(t, err)

	err = refreshRepo.Revoke(t.Context(), params.Token)
	require.NoError(t, err)

	result, err := refreshRepo.GetByToken(t.Context(), params.Token)
	require.NoError(t, err)
	assert.Equal(t, result.IsRevoked, true)
}

func TestRefreshTokenRepository_RevokeAllUserTokens(t *testing.T) {
	logger.Init(LogLevel)

	testDb := SetupTestDb(t)
	defer testDb.TearDown()

	refreshRepo := storage.NewRefreshTokenRepository(testDb.Pool)

	var refreshTokens []model.RefreshToken

	userID := uuid.NewString()

	for i := 0; i < 5; i++ {
		params := model.RefreshToken{
			ID:        uuid.NewString(),
			Token:     uuid.NewString(),
			ExpiresAt: time.Now().Add(5 * time.Minute).UTC(),
			IsRevoked: false,
			UserID:    userID,
			CreatedAt: time.Now(),
		}
		refreshTokens = append(refreshTokens, params)
	}

	for _, params := range refreshTokens {
		err := refreshRepo.Create(t.Context(), &params)
		require.NoError(t, err)
	}

	err := refreshRepo.RevokeAllUsersTokens(t.Context(), userID)
	require.NoError(t, err)

	for _, params := range refreshTokens {
		result, err := refreshRepo.GetByToken(t.Context(), params.Token)
		require.NoError(t, err)
		assert.Equal(t, result.IsRevoked, true)
	}
}

func TestRefreshTokenRepository_DeleteExpired(t *testing.T) {
	logger.Init(LogLevel)

	testDb := SetupTestDb(t)
	defer testDb.TearDown()

	refreshRepo := storage.NewRefreshTokenRepository(testDb.Pool)

	params := &model.RefreshToken{
		ID:        uuid.NewString(),
		Token:     uuid.NewString(),
		ExpiresAt: time.Now().Add(-5 * time.Minute).UTC(),
		IsRevoked: false,
		UserID:    uuid.NewString(),
		CreatedAt: time.Now().Add(-10 * time.Minute).UTC(),
	}

	err := refreshRepo.Create(t.Context(), params)
	require.NoError(t, err)

	err = refreshRepo.DeleteExpired(t.Context())
	require.NoError(t, err)

	result, err := refreshRepo.GetByToken(t.Context(), params.Token)
	require.Error(t, err)
	assert.Equal(t, result, nil)
}

func TestRefreshTokenRepository_DeleteByUserID(t *testing.T) {
	logger.Init(LogLevel)

	testDb := SetupTestDb(t)
	defer testDb.TearDown()

	refreshRepo := storage.NewRefreshTokenRepository(testDb.Pool)

	params := &model.RefreshToken{
		ID:        uuid.NewString(),
		Token:     uuid.NewString(),
		ExpiresAt: time.Now().Add(5 * time.Minute).UTC(),
		IsRevoked: false,
		UserID:    uuid.NewString(),
		CreatedAt: time.Now().UTC(),
	}

	err := refreshRepo.Create(t.Context(), params)
	require.NoError(t, err)

	err = refreshRepo.DeleteByUserId(t.Context(), params.UserID)
	require.NoError(t, err)

	result, err := refreshRepo.GetByToken(t.Context(), params.Token)
	require.Error(t, err)
	assert.Equal(t, result, nil)
}

func TestRefreshTokenRepository_DeleteByToken(t *testing.T) {
	logger.Init(LogLevel)

	testDb := SetupTestDb(t)
	defer testDb.TearDown()

	refreshRepo := storage.NewRefreshTokenRepository(testDb.Pool)

	params := &model.RefreshToken{
		ID:        uuid.NewString(),
		Token:     uuid.NewString(),
		ExpiresAt: time.Now().Add(5 * time.Minute).UTC(),
		IsRevoked: false,
		UserID:    uuid.NewString(),
		CreatedAt: time.Now().UTC(),
	}

	err := refreshRepo.Create(t.Context(), params)
	require.NoError(t, err)

	err = refreshRepo.DeleteByToken(t.Context(), params.Token)
	require.NoError(t, err)

	result, err := refreshRepo.GetByToken(t.Context(), params.Token)
	require.Error(t, err)
	assert.Equal(t, result, nil)
}
