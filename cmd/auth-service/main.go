package main

import (
	"context"
	"database/sql"
	"errors"

	pbAuth "github.com/space-event/auth-service/pkg/authpb"
	"google.golang.org/grpc/reflection"

	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/jackc/pgx/v5/stdlib"
	auth "github.com/space-event/auth-service/internal"
	"github.com/space-event/auth-service/internal/handler"
	"github.com/space-event/auth-service/internal/infrastructure"
	"github.com/space-event/auth-service/internal/logger"
	"github.com/space-event/auth-service/internal/service"
	"github.com/space-event/auth-service/internal/storage"
	pbEmail "github.com/space-event/email-service/pkg/emailpb"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pelletier/go-toml/v2"
	"github.com/pressly/goose/v3"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func LoadConfig() (*auth.Config, error) {
	doc, err := os.ReadFile("config/config.toml")

	if err != nil {
		return nil, err
	}

	expanded := os.ExpandEnv(string(doc))

	var config auth.Config
	err = toml.Unmarshal([]byte(expanded), &config)

	if err != nil {
		return nil, err
	}

	return &config, nil
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

	return goose.Up(db, "migrations")
}

func main() {
	config, err := LoadConfig()

	if err != nil {
		log.Fatalf("Error to load auth config: %v", err)
	}

	logger.Init(config.LogLevel)

	ctx := context.Background()
	db, err := pgxpool.New(ctx, config.Database.Addr)

	if err != nil {
		logger.Error("Error connect to db", "error", err.Error())
		return
	}

	defer db.Close()

	err = runGooseMigrations(db)
	if err != nil {
		logger.Error("Failed to run migrations",
			"error", err.Error(),
			"layer", "service")
		return
	}

	accessTTL, err := time.ParseDuration(config.JWT.AccessTokenTTL)

	if err != nil {
		logger.Error("Error to parser access token ttl", "error", err.Error())
		return
	}

	refreshTTL, err := time.ParseDuration(config.JWT.RefreshTokenTTL)

	if err != nil {
		logger.Error("Error to parser refresh token ttl", "error", err.Error())
		return
	}

	// init
	userRepo := storage.NewUserRepository(db)
	tokenRepo := storage.NewRefreshTokenRepository(db)
	resetPasswordRepo := storage.NewPasswordResetRepository(db)
	hasher := infrastructure.NewBcryptHasher(bcrypt.DefaultCost)
	jwtService := infrastructure.NewJWTService(config.JWT.Secret, accessTTL, refreshTTL)
	valide := validator.New()

	conn, err := grpc.NewClient(config.Service.AddrEmailService, grpc.WithTransportCredentials(insecure.
		NewCredentials()))
	if err != nil {
		logger.Error("Error to connect to email-service", "error", err.Error())
	}
	emailService := pbEmail.NewEmailServiceClient(conn)
	authService := service.NewAuthService(hasher, resetPasswordRepo, tokenRepo, userRepo,
		jwtService)

	defer func(conn *grpc.ClientConn) {
		if err := conn.Close(); err != nil {
			logger.Error("Failed to close gRPC connection", "error", err.Error())
		}
	}(conn)

	// http
	router := chi.NewRouter()
	authHandler := handler.NewAuthHandler(authService, emailService, valide)
	router.Post("/v1/auth/register", authHandler.Register)
	router.Post("/v1/auth/login", authHandler.Login)
	router.Post("/v1/auth/refresh", authHandler.Refresh)
	router.Post("/v1/auth/forgot-password", authHandler.ForgotPassword)
	router.Post("/v1/auth/reset-password", authHandler.ResetPassword)

	server := http.Server{
		Addr:    config.Service.AddrHTTP,
		Handler: router,
	}

	// gRPC
	listener, err := net.Listen("tcp", config.Service.AddrGRPC)
	if err != nil {
		logger.Error("Failed to listen",
			"address", config.Service.AddrGRPC,
			"error", err.Error())
	}
	authGRPCServer := handler.NewAuthGRPCServer(valide, authService, emailService, config.Service.URLFrontend)
	grpcServer := grpc.NewServer()
	pbAuth.RegisterAuthServiceServer(grpcServer, authGRPCServer)
	reflection.Register(grpcServer)

	// channels
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	errHTTPChan := make(chan error, 1)
	errGRPCChan := make(chan error, 1)

	logger.Info("Auth-service http serve on",
		"address", config.Service.AddrHTTP)
	go func() {
		if err = server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errHTTPChan <- err
		}
	}()

	logger.Info("Auth-service gRPC serve on",
		"address", config.Service.AddrGRPC)
	go func() {
		if err = grpcServer.Serve(listener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			errGRPCChan <- err
		}
	}()

	select {
	case <-signalChan:

		logger.Info("Shutting down gracefully...")

		ctxShutdown, cancel := context.WithTimeout(context.Background(), time.Second*30)
		defer cancel()

		if err = server.Shutdown(ctxShutdown); err != nil {
			logger.Error("HTTP server shutdown error", "error", err.Error())
		}

		if err = conn.Close(); err != nil {
			logger.Error("gRPC connection close error", "error", err.Error())
		}

		grpcServer.GracefulStop()

	case err = <-errHTTPChan:
		logger.Error("Server http error", "error", err.Error())

	case err = <-errGRPCChan:
		logger.Error("Server gRPC error", "error", err.Error())
	}

}
