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

func TestResetPasswordRepository_Create(t *testing.T) {

	logger.Init(LogLevel)

	testDb := SetupTestDb(t)
	defer testDb.TearDown()

	resetPasswordRepo := storage.NewPasswordResetRepository(testDb.Pool)

	params := &model.ResetPassword{
		ID:        uuid.NewString(),
		Email:     TestEmail,
		TokenHash: uuid.NewString(),
		ExpiresAt: time.Now().Add(5 * time.Minute).UTC(),
		CreatedAt: time.Now().UTC(),
	}

	err := resetPasswordRepo.Create(t.Context(), params)
	require.NoError(t, err)

	result, err := resetPasswordRepo.GetByToken(t.Context(), params.TokenHash)
	require.NoError(t, err)
	assert.Equal(t, result.ID, params.ID)
	assert.Equal(t, result.Email, params.Email)
	assert.Equal(t, result.TokenHash, params.TokenHash)
	assert.Equal(t, result.ExpiresAt.UTC(), params.ExpiresAt.UTC())
	assert.Equal(t, result.CreatedAt.UTC(), params.CreatedAt.UTC())
}

func TestResetPasswordRepository_Create_DuplicateID(t *testing.T) {

	logger.Init(LogLevel)

	testDb := SetupTestDb(t)
	defer testDb.TearDown()

	resetPasswordRepo := storage.NewPasswordResetRepository(testDb.Pool)

	params := &model.ResetPassword{
		ID:        uuid.NewString(),
		Email:     TestEmail,
		TokenHash: uuid.NewString(),
		ExpiresAt: time.Now().Add(5 * time.Minute).UTC(),
		CreatedAt: time.Now().UTC(),
	}

	err := resetPasswordRepo.Create(t.Context(), params)
	require.NoError(t, err)

	err = resetPasswordRepo.Create(t.Context(), params)
	require.Error(t, err)
}

func TestResetPasswordRepository_Create_DuplicateTokenHash(t *testing.T) {

	logger.Init(LogLevel)

	testDb := SetupTestDb(t)
	defer testDb.TearDown()

	resetPasswordRepo := storage.NewPasswordResetRepository(testDb.Pool)

	tokenHash := uuid.NewString()

	params1 := &model.ResetPassword{
		ID:        uuid.NewString(),
		Email:     TestEmail,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(5 * time.Minute).UTC(),
		CreatedAt: time.Now().UTC(),
	}

	params2 := &model.ResetPassword{
		ID:        uuid.NewString(),
		Email:     TestEmailAnother,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(5 * time.Minute).UTC(),
		CreatedAt: time.Now().UTC(),
	}

	err := resetPasswordRepo.Create(t.Context(), params1)

	require.NoError(t, err)

	err = resetPasswordRepo.Create(t.Context(), params2)

	require.Error(t, err)
}

func TestResetPasswordRepository_CreateWithDuplicateEmail(t *testing.T) {
	logger.Init(LogLevel)

	testDb := SetupTestDb(t)
	defer testDb.TearDown()

	resetPasswordRepo := storage.NewPasswordResetRepository(testDb.Pool)

	tokens := make([]*model.ResetPassword, 5)
	for i := 0; i < 5; i++ {
		token := &model.ResetPassword{
			ID:        uuid.NewString(),
			Email:     TestEmail,
			TokenHash: uuid.NewString(),
			ExpiresAt: time.Now().UTC().Add(5 * time.Minute),
			CreatedAt: time.Now().UTC(),
		}
		err := resetPasswordRepo.Create(t.Context(), token)
		require.NoError(t, err)
		tokens[i] = token
	}

	for _, token := range tokens {
		result, err := resetPasswordRepo.GetByToken(t.Context(), token.TokenHash)
		require.NoError(t, err)
		assert.Equal(t, token.Email, result.Email)
	}
}

func TestResetPasswordRepository_GetByToken_NoFound(t *testing.T) {
	logger.Init(LogLevel)

	testDb := SetupTestDb(t)
	defer testDb.TearDown()

	resetPasswordRepo := storage.NewPasswordResetRepository(testDb.Pool)

	result, err := resetPasswordRepo.GetByToken(t.Context(), "123213213")
	require.Error(t, err)
	assert.Equal(t, result, nil)
}

func TestResetPasswordRepository_GetByToken_Expired(t *testing.T) {

	logger.Init(LogLevel)

	testDb := SetupTestDb(t)
	defer testDb.TearDown()

	resetPasswordRepo := storage.NewPasswordResetRepository(testDb.Pool)

	params := &model.ResetPassword{
		ID:        uuid.NewString(),
		Email:     TestEmail,
		TokenHash: uuid.NewString(),
		ExpiresAt: time.Now().Add(-1 * time.Hour).UTC(),
		CreatedAt: time.Now().UTC().Add(-2 * time.Hour).UTC(),
	}

	err := resetPasswordRepo.Create(t.Context(), params)
	require.NoError(t, err)

	result, err := resetPasswordRepo.GetByToken(t.Context(), params.TokenHash)
	require.NoError(t, err)

	assert.Equal(t, result.ExpiresAt.Before(time.Now().UTC()), true)
}

func TestResetPasswordRepository_DeleteByHash(t *testing.T) {
	logger.Init(LogLevel)

	testDb := SetupTestDb(t)
	defer testDb.TearDown()

	resetPasswordRepo := storage.NewPasswordResetRepository(testDb.Pool)

	params := &model.ResetPassword{
		ID:        uuid.NewString(),
		Email:     TestEmail,
		TokenHash: uuid.NewString(),
		ExpiresAt: time.Now().Add(5 * time.Minute).UTC(),
		CreatedAt: time.Now().UTC(),
	}

	err := resetPasswordRepo.Create(t.Context(), params)
	require.NoError(t, err)

	_, err = resetPasswordRepo.GetByToken(t.Context(), params.TokenHash)
	require.NoError(t, err)

	err = resetPasswordRepo.DeleteByToken(t.Context(), params.TokenHash)
	require.NoError(t, err)

	_, err = resetPasswordRepo.GetByToken(t.Context(), params.TokenHash)
	require.Error(t, err)
}

func TestResetPasswordRepository_DeleteExpired(t *testing.T) {

	logger.Init(LogLevel)

	testDb := SetupTestDb(t)
	defer testDb.TearDown()

	resetPasswordRepo := storage.NewPasswordResetRepository(testDb.Pool)

	params := &model.ResetPassword{
		ID:        uuid.NewString(),
		Email:     TestEmail,
		TokenHash: uuid.NewString(),
		ExpiresAt: time.Now().Add(-1 * time.Hour).UTC(),
		CreatedAt: time.Now().UTC().Add(-2 * time.Hour).UTC(),
	}

	err := resetPasswordRepo.Create(t.Context(), params)
	require.NoError(t, err)

	_, err = resetPasswordRepo.GetByToken(t.Context(), params.TokenHash)
	require.NoError(t, err)

	err = resetPasswordRepo.DeleteExpired(t.Context())
	require.NoError(t, err)

	_, err = resetPasswordRepo.GetByToken(t.Context(), params.TokenHash)
	require.Error(t, err)
}
