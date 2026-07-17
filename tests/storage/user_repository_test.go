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

func TestUserRepository_Create(t *testing.T) {

	logger.Init(LogLevel)

	testDb := SetupTestDb(t)
	defer testDb.TearDown()

	userRepo := storage.NewUserRepository(testDb.Pool)

	user := &model.User{
		ID:           uuid.NewString(),
		Email:        TestEmail,
		PasswordHash: uuid.NewString(),
		CreatedAt:    time.Now().UTC(),
		Firstname:    TestFirstname,
		Lastname:     TestLastname,
	}

	err := userRepo.Create(t.Context(), user)
	require.NoError(t, err)

	result, err := userRepo.GetByID(t.Context(), user.ID)
	require.NoError(t, err)
	assert.Equal(t, user.ID, result.ID)
	assert.Equal(t, user.Email, result.Email)
	assert.Equal(t, user.PasswordHash, result.PasswordHash)
	assert.Equal(t, user.Firstname, result.Firstname)
	assert.Equal(t, user.Lastname, result.Lastname)
	assert.Equal(t, user.CreatedAt.UTC(), result.CreatedAt.UTC())
}

func TestUserRepository_Create_DuplicateID(t *testing.T) {
	logger.Init(LogLevel)

	testDb := SetupTestDb(t)
	defer testDb.TearDown()

	userRepo := storage.NewUserRepository(testDb.Pool)

	id := uuid.NewString()
	user1 := &model.User{
		ID:           id,
		Email:        TestEmail,
		PasswordHash: uuid.NewString(),
		CreatedAt:    time.Now().UTC(),
		Firstname:    TestFirstname,
		Lastname:     TestLastname,
	}

	user2 := &model.User{
		ID:           id,
		Email:        TestEmailAnother,
		PasswordHash: uuid.NewString(),
		CreatedAt:    time.Now().UTC(),
		Firstname:    TestFirstname,
		Lastname:     TestLastname,
	}

	err := userRepo.Create(t.Context(), user1)
	require.NoError(t, err)

	err = userRepo.Create(t.Context(), user2)
	require.Error(t, err)
}

func TestUserRepository_Create_DuplicateEmail(t *testing.T) {

	logger.Init(LogLevel)

	testDb := SetupTestDb(t)
	defer testDb.TearDown()

	userRepo := storage.NewUserRepository(testDb.Pool)

	user1 := &model.User{
		ID:           uuid.NewString(),
		Email:        TestEmail,
		PasswordHash: uuid.NewString(),
		CreatedAt:    time.Now().UTC(),
		Firstname:    TestFirstname,
		Lastname:     TestLastname,
	}

	user2 := &model.User{
		ID:           uuid.NewString(),
		Email:        TestEmail,
		PasswordHash: uuid.NewString(),
		CreatedAt:    time.Now().UTC(),
		Firstname:    TestFirstname,
		Lastname:     TestLastname,
	}

	err := userRepo.Create(t.Context(), user1)
	require.NoError(t, err)

	err = userRepo.Create(t.Context(), user2)
	require.Error(t, err)
}

func TestUserRepository_GetByEmail_Exist(t *testing.T) {
	logger.Init(LogLevel)

	testDb := SetupTestDb(t)
	defer testDb.TearDown()

	userRepo := storage.NewUserRepository(testDb.Pool)

	user := &model.User{
		ID:           uuid.NewString(),
		Email:        TestEmail,
		PasswordHash: uuid.NewString(),
		CreatedAt:    time.Now().UTC(),
		Firstname:    TestFirstname,
		Lastname:     TestLastname,
	}

	err := userRepo.Create(t.Context(), user)
	require.NoError(t, err)

	result, err := userRepo.GetByEmail(t.Context(), user.Email)
	require.NoError(t, err)
	assert.Equal(t, user.ID, result.ID)
	assert.Equal(t, user.Email, result.Email)
	assert.Equal(t, user.PasswordHash, result.PasswordHash)
	assert.Equal(t, user.Firstname, result.Firstname)
	assert.Equal(t, user.Lastname, result.Lastname)
	assert.Equal(t, user.CreatedAt.UTC(), result.CreatedAt.UTC())
}

func TestUserRepository_GetByEmail_NoFound(t *testing.T) {
	logger.Init(LogLevel)

	testDb := SetupTestDb(t)
	defer testDb.TearDown()

	userRepo := storage.NewUserRepository(testDb.Pool)

	result, err := userRepo.GetByEmail(t.Context(), TestEmail)
	require.Error(t, err)
	assert.Equal(t, result, nil)
}

func TestUserRepository_GetByID_Exist(t *testing.T) {
	logger.Init(LogLevel)

	testDb := SetupTestDb(t)
	defer testDb.TearDown()

	userRepo := storage.NewUserRepository(testDb.Pool)

	user := &model.User{
		ID:           uuid.NewString(),
		Email:        TestEmail,
		PasswordHash: uuid.NewString(),
		CreatedAt:    time.Now().UTC(),
		Firstname:    TestFirstname,
		Lastname:     TestLastname,
	}

	err := userRepo.Create(t.Context(), user)
	require.NoError(t, err)

	result, err := userRepo.GetByID(t.Context(), user.ID)
	require.NoError(t, err)
	assert.Equal(t, user.ID, result.ID)
	assert.Equal(t, user.Email, result.Email)
	assert.Equal(t, user.PasswordHash, result.PasswordHash)
	assert.Equal(t, user.Firstname, result.Firstname)
	assert.Equal(t, user.Lastname, result.Lastname)
	assert.Equal(t, user.CreatedAt.UTC(), result.CreatedAt.UTC())
}

func TestUserRepository_GetByID_NoFound(t *testing.T) {
	logger.Init(LogLevel)

	testDb := SetupTestDb(t)
	defer testDb.TearDown()

	userRepo := storage.NewUserRepository(testDb.Pool)

	result, err := userRepo.GetByID(t.Context(), uuid.NewString())
	require.Error(t, err)
	assert.Equal(t, result, nil)
}

func TestUserRepository_Exist_True(t *testing.T) {
	logger.Init(LogLevel)

	testDb := SetupTestDb(t)
	defer testDb.TearDown()

	userRepo := storage.NewUserRepository(testDb.Pool)

	user := &model.User{
		ID:           uuid.NewString(),
		Email:        TestEmail,
		PasswordHash: uuid.NewString(),
		CreatedAt:    time.Now().UTC(),
		Firstname:    TestFirstname,
		Lastname:     TestLastname,
	}

	err := userRepo.Create(t.Context(), user)
	require.NoError(t, err)

	exists, err := userRepo.Exists(t.Context(), user.Email)
	require.NoError(t, err)
	require.Equal(t, exists, true)
}

func TestUserRepository_Exist_False(t *testing.T) {

	logger.Init(LogLevel)

	testDb := SetupTestDb(t)
	defer testDb.TearDown()

	userRepo := storage.NewUserRepository(testDb.Pool)

	exists, err := userRepo.Exists(t.Context(), TestEmail)
	require.NoError(t, err)
	require.Equal(t, exists, false)
}

func TestUserRepository_Delete_Exist(t *testing.T) {
	logger.Init(LogLevel)

	testDb := SetupTestDb(t)
	defer testDb.TearDown()

	userRepo := storage.NewUserRepository(testDb.Pool)

	user := &model.User{
		ID:           uuid.NewString(),
		Email:        TestEmail,
		PasswordHash: uuid.NewString(),
		CreatedAt:    time.Now().UTC(),
		Firstname:    TestFirstname,
		Lastname:     TestLastname,
	}

	err := userRepo.Create(t.Context(), user)
	require.NoError(t, err)

	err = userRepo.Delete(t.Context(), user.ID)
	require.NoError(t, err)

	exists, err := userRepo.Exists(t.Context(), user.Email)
	require.NoError(t, err)
	assert.Equal(t, exists, false)
}

func TestUserRepository_Delete_NoFound(t *testing.T) {
	logger.Init(LogLevel)

	testDb := SetupTestDb(t)
	defer testDb.TearDown()

	userRepo := storage.NewUserRepository(testDb.Pool)

	err := userRepo.Delete(t.Context(), uuid.NewString())
	require.Error(t, err)

}

func TestUserRepository_UpdatePassword(t *testing.T) {
	logger.Init(LogLevel)

	testDb := SetupTestDb(t)
	defer testDb.TearDown()

	userRepo := storage.NewUserRepository(testDb.Pool)

	user := &model.User{
		ID:           uuid.NewString(),
		Email:        TestEmail,
		PasswordHash: uuid.NewString(),
		CreatedAt:    time.Now().UTC(),
		Firstname:    TestFirstname,
		Lastname:     TestLastname,
	}

	err := userRepo.Create(t.Context(), user)
	require.NoError(t, err)

	newHashPassword := uuid.NewString()

	err = userRepo.UpdatePassword(t.Context(), user.Email, newHashPassword)
	require.NoError(t, err)

	result, err := userRepo.GetByEmail(t.Context(), user.Email)
	require.NoError(t, err)
	assert.Equal(t, user.Email, result.Email)
	assert.Equal(t, result.PasswordHash, newHashPassword)
}
