package storage

import (
	"context"
	"database/sql"
	"log"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/space-event/auth-service/internal/logger"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	LogLevel         = "error"
	TestEmail        = "test@gmail.com"
	TestFirstname    = "test-firstname"
	TestLastname     = "test-lastname"
	TestEmailAnother = "test2@gmail.com"
)

type TestDb struct {
	Pool             *pgxpool.Pool
	Container        *postgres.PostgresContainer
	ConnectionString string
}

func SetupTestDb(t *testing.T) *TestDb {

	ctx := context.Background()

	postgresContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("test-db"),
		postgres.WithUsername("usertest"),
		postgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(wait.ForLog(
			"database system is ready to accept connections").
			WithOccurrence(2).WithStartupTimeout(15*time.Second)),
	)

	if err != nil {
		t.Fatal("Failed to start postgres container", err)
	}

	connectionString, err := postgresContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal("Failed to get connection string", err)
	}

	pool, err := pgxpool.New(ctx, connectionString)
	if err != nil {
		t.Fatal("Failed to connect DB", err)
	}

	err = runGooseMigrations(pool)
	if err != nil {
		t.Fatal("Failed to run migrations", err)
	}

	return &TestDb{
		Pool:             pool,
		Container:        postgresContainer,
		ConnectionString: connectionString,
	}

}

func (tdb *TestDb) TearDown() {
	if tdb.Pool != nil {
		tdb.Pool.Close()
	}
	if tdb.Container != nil {
		err := tdb.Container.Terminate(context.Background())
		if err != nil {
			log.Fatal("Failed to terminate container", err)
		}
	}
}

func runGooseMigrations(pool *pgxpool.Pool) error {
	db := stdlib.OpenDBFromPool(pool)
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {
			logger.Error("Failed to close db",
				"error", err.Error())
		}
	}(db)

	if err := goose.SetDialect("postgres"); err != nil {
		logger.Error("Failed to set dialect goose",
			"error", err.Error())
		return err
	}

	return goose.Up(db, "../../migrations")
}
