package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/space-event/auth-service/internal"
	"github.com/space-event/auth-service/internal/logger"
	"github.com/space-event/auth-service/internal/service"
	pb "github.com/space-event/auth-service/pkg/authpb"
	"github.com/space-event/auth-service/pkg/dto"
	email "github.com/space-event/email-service/pkg/emailpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type AuthGRPCServer struct {
	pb.UnimplementedAuthServiceServer
	authService  *service.AuthService
	validate     *validator.Validate
	emailService email.EmailServiceClient
	config       *internal.Config
}

func NewAuthGRPCServer(validate *validator.Validate, authService *service.AuthService,
	emailService email.EmailServiceClient, config *internal.Config) *AuthGRPCServer {
	return &AuthGRPCServer{validate: validate, authService: authService,
		emailService: emailService, config: config}
}

func (s *AuthGRPCServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.AuthResponse,
	error) {
	start := time.Now()

	dtoReq := dto.LoginRequest{
		Email:    req.Email,
		Password: req.Password,
	}

	if err := s.validate.Struct(dtoReq); err != nil {
		logger.Error("gRPC Login validation error",
			"layer", "gRPC",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return nil, status.Errorf(codes.InvalidArgument, "%s", err.Error())
	}

	tokens, err := s.authService.Login(ctx, dtoReq)
	if err != nil {
		logger.Error("gRPC Login failed",
			"layer", "gRPC",
			"error", err.Error(),
			"email", req.Email,
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return nil, status.Errorf(codes.Unauthenticated, "%s", err.Error())
	}

	logger.Info("User logged in via gRPC",
		"layer", "gRPC",
		"email", dtoReq.Email,
		"duration_ms", time.Since(start).Milliseconds(),
	)

	return &pb.AuthResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresAt:    timestamppb.New(tokens.ExpiresAt),
	}, nil
}

func (s *AuthGRPCServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.AuthResponse, error) {
	start := time.Now()

	dtoReq := dto.RegisterRequest{
		Email:     req.Email,
		Password:  req.Password,
		Firstname: req.Firstname,
		Lastname:  req.Lastname,
	}

	if err := s.validate.Struct(dtoReq); err != nil {
		logger.Error("gRPC Register validation error",
			"layer", "gRPC",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return nil, status.Errorf(codes.InvalidArgument, "%s", err.Error())
	}

	tokens, err := s.authService.Register(ctx, dtoReq)
	if err != nil {
		logger.Error("gRPC Register failed",
			"layer", "gRPC",
			"error", err.Error(),
			"email", req.Email,
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return nil, status.Errorf(codes.Unauthenticated, "%s", err.Error())
	}

	logger.Info("User registered via gRPC",
		"layer", "gRPC",
		"email", req.Email,
		"duration_ms", time.Since(start).Milliseconds(),
	)

	return &pb.AuthResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresAt:    timestamppb.New(tokens.ExpiresAt),
	}, nil
}

func (s *AuthGRPCServer) Refresh(ctx context.Context, req *pb.RefreshRequest) (*pb.AuthResponse,
	error) {
	start := time.Now()

	if req.RefreshToken == "" {
		logger.Error("gRPC Refresh validation error",
			"layer", "gRPC",
			"error", "refresh_token is required",
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return nil, status.Errorf(codes.InvalidArgument, "refresh_token is required")
	}

	tokens, err := s.authService.RefreshAccessToken(ctx, req.RefreshToken)
	if err != nil {
		logger.Error("gRPC Refresh failed",
			"layer", "gprc",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return nil, status.Errorf(codes.AlreadyExists, "%s", err.Error())
	}

	logger.Info("Refresh token rotated via gRPC",
		"layer", "gRPC",
		"duration_ms", time.Since(start).Milliseconds(),
	)

	return &pb.AuthResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresAt:    timestamppb.New(tokens.ExpiresAt),
	}, nil
}

func (s *AuthGRPCServer) ForgotPassword(ctx context.Context,
	req *pb.ForgotPasswordRequest) (*pb.ForgotPasswordResponse, error) {
	start := time.Now()

	dtoReq := dto.ForgotPasswordRequest{
		Email: req.Email,
	}

	if err := s.validate.Struct(dtoReq); err != nil {
		logger.Error("gRPC ForgotPassword validation error",
			"layer", "gRPC",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return nil, status.Errorf(codes.InvalidArgument, "%s", err.Error())
	}

	if err := s.authService.VerifyEmail(ctx, dtoReq.Email); err != nil {
		logger.Error("gRPC Verify failed",
			"layer", "gRPC",
			"error", err.Error(),
			"email", req.Email,
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return nil, status.Errorf(codes.NotFound, "%s", err.Error())
	}

	token, err := s.authService.GenerateToken()
	if err != nil {
		logger.Error("gRPC Generate token failed",
			"layer", "gRPC",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])

	urlReset := fmt.Sprintf("%s/reset-password?token=%s", s.config.Service.URLFrontend, token)

	res, err := s.emailService.Send(ctx, &email.EmailRequest{
		EmailTarget: req.Email,
		MessageText: fmt.Sprintf(s.config.Service.ResetPasswordMessage, urlReset),
		ContentType: "text/html",
		Subject:     "Reset password",
	})

	if err != nil {
		logger.Error("gRPC Send email failed",
			"layer", "gRPC",
			"error", err.Error(),
			"email", req.Email,
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	if !res.Success {
		logger.Error("gRPC Send email failed",
			"layer", "gRPC",
			"error", res.Error,
			"email", req.Email,
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return nil, status.Errorf(codes.Internal, "%s", res.Error)
	}

	if err := s.authService.SaveHashToken(ctx, dtoReq.Email, tokenHash); err != nil {
		logger.Error("gRPC Save token failed",
			"layer", "gRPC",
			"error", err.Error(),
			"email", req.Email,
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return nil, status.Errorf(codes.Unauthenticated, "%s", err.Error())
	}

	logger.Info("Password reset email sent via gRPC",
		"layer", "gRPC",
		"email", req.Email,
		"duration_ms", time.Since(start).Milliseconds(),
	)

	return &pb.ForgotPasswordResponse{}, nil
}

func (s *AuthGRPCServer) ResetPassword(ctx context.Context, req *pb.ResetPasswordRequest) (*pb.ResetPasswordResponse,
	error) {
	start := time.Now()

	dtoReq := dto.ResetPasswordRequest{
		Token:    req.Token,
		Password: req.Password,
	}

	if err := s.validate.Struct(dtoReq); err != nil {
		logger.Error("gRPC ResetPassword validation error",
			"layer", "handler",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return nil, status.Errorf(codes.InvalidArgument, "%s", err.Error())
	}

	if err := s.authService.ResetPassword(ctx, dtoReq.Token, dtoReq.Password); err != nil {
		logger.Error("gRPC Reset password failed",
			"layer", "gRPC",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	logger.Info("Password reset successfully",
		"layer", "handler",
		"duration_ms", time.Since(start).Milliseconds(),
	)

	return &pb.ResetPasswordResponse{}, nil
}
