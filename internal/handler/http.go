package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/space-event/auth-service/internal/logger"
	"github.com/space-event/auth-service/internal/service"
	"github.com/space-event/auth-service/pkg/dto"
	email "github.com/space-event/email-service/pkg/emailpb"
)

type AuthHandler struct {
	authService  *service.AuthService
	emailService email.EmailServiceClient
	validate     *validator.Validate
}

const (
	ErrInvalidBody         = "invalid body"
	ErrMissingRefreshToken = "missing refresh token"
	ErrInvalidRefreshToken = "invalid refresh token"
	ErrInternalServer      = "internal server error"
)

func NewAuthHandler(authService *service.AuthService, emailService email.EmailServiceClient,
	validate *validator.Validate,
) *AuthHandler {
	return &AuthHandler{authService: authService, emailService: emailService, validate: validate}
}

func SetError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": message,
	})
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var req dto.RegisterRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("HTTP Register error",
			"layer", "handler",
			"error", "invalid_body",
			"duration_ms", time.Since(start).Milliseconds(),
		)
		SetError(w, ErrInvalidBody, http.StatusBadRequest)
		return
	}

	if err := h.validate.Struct(req); err != nil {
		logger.Error("HTTP Register validation error",
			"layer", "handler",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		SetError(w, ErrInvalidBody, http.StatusBadRequest)
		return
	}

	tokens, err := h.authService.Register(r.Context(), req)
	if err != nil {
		logger.Error("Failed to register",
			"layer", "handler",
			"error", err.Error(),
			"email", req.Email,
			"duration_ms", time.Since(start).Milliseconds(),
		)
		SetError(w, err.Error(), http.StatusBadRequest)
		return
	}

	h.setRefreshTokenCookie(w, tokens.RefreshToken)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": tokens.AccessToken,
		"expires_at":   tokens.ExpiresAt,
	}); err != nil {
		logger.Error("Failed to encode response",
			"layer", "handler",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		SetError(w, ErrInternalServer, http.StatusInternalServerError)
		return
	}

	logger.Info("User registered",
		"layer", "handler",
		"email", req.Email,
		"duration_ms", time.Since(start).Milliseconds(),
		"ip", r.RemoteAddr,
	)
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var req dto.LoginRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("HTTP Login error",
			"layer", "handler",
			"error", "invalid_body",
			"duration_ms", time.Since(start).Milliseconds(),
		)
		SetError(w, ErrInvalidBody, http.StatusBadRequest)
		return
	}

	if err := h.validate.Struct(req); err != nil {
		logger.Error("HTTP Login validation error",
			"layer", "handler",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		SetError(w, ErrInvalidBody, http.StatusBadRequest)
		return
	}

	tokens, err := h.authService.Login(r.Context(), req)
	if err != nil {
		logger.Error("Failed to login",
			"layer", "handler",
			"error", err.Error(),
			"email", req.Email,
			"duration_ms", time.Since(start).Milliseconds(),
		)
		SetError(w, err.Error(), http.StatusBadRequest)
		return
	}

	h.setRefreshTokenCookie(w, tokens.RefreshToken)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": tokens.AccessToken,
		"expires_at":   tokens.ExpiresAt,
	}); err != nil {
		logger.Error("Failed to encode response",
			"layer", "handler",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		SetError(w, ErrInternalServer, http.StatusInternalServerError)
		return
	}

	logger.Info("User logged in",
		"layer", "handler",
		"email", req.Email,
		"duration_ms", time.Since(start).Milliseconds(),
		"ip", r.RemoteAddr,
	)
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		logger.Error("Missing refresh token",
			"layer", "handler",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		SetError(w, ErrMissingRefreshToken, http.StatusUnauthorized)
		return
	}

	tokens, err := h.authService.RefreshAccessToken(r.Context(), cookie.Value)
	if err != nil {
		logger.Error("Failed to refresh token",
			"layer", "handler",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		SetError(w, ErrInvalidRefreshToken, http.StatusUnauthorized)
		return
	}

	h.setRefreshTokenCookie(w, tokens.RefreshToken)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": tokens.AccessToken,
		"expires_at":   tokens.ExpiresAt,
	}); err != nil {
		logger.Error("Failed to encode response",
			"layer", "handler",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		SetError(w, ErrInternalServer, http.StatusInternalServerError)
		return
	}

	logger.Info("Refresh token rotated",
		"layer", "handler",
		"duration_ms", time.Since(start).Milliseconds(),
		"ip", r.RemoteAddr,
	)
}

func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var req dto.ForgotPasswordRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("HTTP ForgotPassword error",
			"layer", "handler",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		SetError(w, ErrInvalidBody, http.StatusBadRequest)
		return
	}

	if err := h.validate.Struct(req); err != nil {
		logger.Error("HTTP ForgotPassword validation error",
			"layer", "handler",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		SetError(w, ErrInvalidBody, http.StatusBadRequest)
		return
	}

	if err := h.authService.VerifyEmail(r.Context(), req.Email); err != nil {
		logger.Error("Failed to verify email",
			"layer", "handler",
			"error", err.Error(),
			"email", req.Email,
			"duration_ms", time.Since(start).Milliseconds(),
		)
		SetError(w, err.Error(), http.StatusBadRequest)
		return
	}

	token, err := h.authService.GenerateToken()
	if err != nil {
		logger.Error("Failed to generate token",
			"layer", "handler",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		SetError(w, ErrInternalServer, http.StatusInternalServerError)
		return
	}

	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])

	res, err := h.emailService.Send(r.Context(), &email.EmailRequest{
		EmailTarget: req.Email,
		MessageText: fmt.Sprintf("http://localhost:5173/reset-password?token=%s", token),
		ContentType: "text/html",
		Subject:     "Reset password",
	})
	if err != nil {
		logger.Error("Failed to send email",
			"layer", "handler",
			"error", err.Error(),
			"email", req.Email,
			"duration_ms", time.Since(start).Milliseconds(),
		)
		SetError(w, ErrInternalServer, http.StatusInternalServerError)
		return
	}

	if !res.Success {
		logger.Error("Failed to send email",
			"layer", "handler",
			"error", res.Error,
			"email", req.Email,
			"duration_ms", time.Since(start).Milliseconds(),
		)
		SetError(w, ErrInternalServer, http.StatusInternalServerError)
		return
	}

	if err := h.authService.SaveHashToken(r.Context(), req.Email, tokenHash); err != nil {
		logger.Error("Failed to save token",
			"layer", "handler",
			"error", err.Error(),
			"email", req.Email,
			"duration_ms", time.Since(start).Milliseconds(),
		)
		SetError(w, ErrInternalServer, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)

	logger.Info("Password reset email sent",
		"layer", "handler",
		"email", req.Email,
		"duration_ms", time.Since(start).Milliseconds(),
		"ip", r.RemoteAddr,
	)
}

func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var req dto.ResetPasswordRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("HTTP ResetPassword error",
			"layer", "handler",
			"error", "invalid_body",
			"duration_ms", time.Since(start).Milliseconds(),
		)
		SetError(w, ErrInvalidBody, http.StatusBadRequest)
		return
	}

	if err := h.validate.Struct(req); err != nil {
		logger.Error("HTTP ResetPassword validation error",
			"layer", "handler",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		SetError(w, ErrInvalidBody, http.StatusBadRequest)
		return
	}

	if err := h.authService.ResetPassword(r.Context(), req.Token, req.Password); err != nil {
		logger.Error("Failed to reset password",
			"layer", "handler",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		SetError(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)

	logger.Info("Password reset successfully",
		"layer", "handler",
		"duration_ms", time.Since(start).Milliseconds(),
		"ip", r.RemoteAddr,
	)
}

func (h *AuthHandler) setRefreshTokenCookie(w http.ResponseWriter, refreshToken string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   7 * 24 * 3600,
	})
}
