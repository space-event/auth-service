package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	auth "github.com/space-event/auth-service/internal"
	"github.com/space-event/auth-service/internal/handler"
	"github.com/space-event/auth-service/internal/infrastructure"
	"github.com/space-event/auth-service/internal/service"
	"github.com/space-event/auth-service/internal/storage"
	pb "github.com/space-event/email-service/pkg/emailpb"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pelletier/go-toml/v2"
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

func main() {
	config, err := LoadConfig()

	if err != nil {
		log.Fatalf("Error to load auth config: %v", err)
	}

	ctx := context.Background()
	db, err := pgxpool.New(ctx, config.Database.Addr)

	if err != nil {
		log.Fatalf("Error connect to db: %v", err.Error())
	}

	defer db.Close()

	accessTTL, err := time.ParseDuration(config.JWT.AccessTokenTTL)

	if err != nil {
		log.Fatalf("Error to parser access token ttl: %v", err.Error())
	}

	refreshTTL, err := time.ParseDuration(config.JWT.RefreshTokenTTL)

	if err != nil {
		log.Fatalf("Error to parser refresh token ttl: %v", err.Error())
	}

	userRepo := storage.NewUserRepository(db)
	tokenRepo := storage.NewRefreshTokenRepository(db)
	resetPasswordRepo := storage.NewPasswordResetRepository(db)
	hasher := infrastructure.NewBcryptHasher(bcrypt.DefaultCost)
	jwtService := infrastructure.NewJWTService(config.JWT.Secret, accessTTL, refreshTTL)

	conn, err := grpc.NewClient("email-service:50051", grpc.WithTransportCredentials(insecure.
		NewCredentials()))
	if err != nil {
		log.Fatal(err.Error())
	}
	defer conn.Close()

	emailService := pb.NewEmailServiceClient(conn)

	authService := service.NewAuthService(hasher, resetPasswordRepo, tokenRepo, userRepo,
		jwtService)

	router := chi.NewRouter()

	authHandler := handler.NewAuthHandler(authService, emailService)

	router.Post("/v1/auth/register", authHandler.RegisterHandler)

	router.Post("/v1/auth/login", authHandler.Login)

	router.Post("/v1/auth/refresh", authHandler.Refresh)

	router.Post("/v1/auth/forgot-password", authHandler.ForgotPassword)

	router.Post("/v1/auth/reset-password", authHandler.ResetPassword)

	server := http.Server{
		Addr:    ":8081",
		Handler: router,
	}

	log.Println("Start auth")
	if err = server.ListenAndServe(); err != nil {
		log.Fatalf("Error to start api-gateway: %v", err.Error())
	}
}
