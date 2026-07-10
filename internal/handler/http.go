package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/space-event/auth-service/internal/logger"
	"github.com/go-playground/validator/v10"
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

func (h *AuthHandler) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var req dto.RegisterRequest

	start := time.Now()
	logger.Debug("Register request started", "ip", r.RemoteAddr, "user_agent", r.UserAgent())

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("HTTP Register error", "error", "invalid_body")
		SetError(w, ErrInvalidBody, http.StatusBadRequest)
		return
	}

	if err := h.validate.Struct(req); err != nil {
		SetError(w, ErrInvalidBody, http.StatusBadRequest)
		return
	}

	tokens, err := h.authService.Register(r.Context(), req)

	if err != nil {
		logger.Error("Failed to register", "error", err.Error())
		SetError(w, err.Error(), http.StatusBadRequest)
		return
	}

	h.setRefreshTokenCookie(w, tokens.RefreshToken)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	err = json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": tokens.AccessToken,
		"expires_at":   tokens.ExpiresAt,
	})

	if err != nil {
		logger.Error("Failed to encode response", "error", err.Error())
		SetError(w, err.Error(), http.StatusBadRequest)
		return
	}

	logger.Debug("Registered successfully",
		"duration_ms", time.Since(start).Milliseconds(),
		"ip", r.RemoteAddr,
	)

}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req dto.LoginRequest

	start := time.Now()
	logger.Debug("Login request started", "ip", r.RemoteAddr, "user_agent", r.UserAgent())

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("HTTP Login error", "error", "invalid_body")
		SetError(w, ErrInvalidBody, http.StatusBadRequest)
		return
	}

	if err := h.validate.Struct(req); err != nil {
		SetError(w, ErrInvalidBody, http.StatusBadRequest)
		return
	}

	tokens, err := h.authService.Login(r.Context(), req)

	if err != nil {
		logger.Info("Failed to login", "error", err.Error())
		SetError(w, err.Error(), http.StatusBadRequest)
		return
	}

	h.setRefreshTokenCookie(w, tokens.RefreshToken)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": tokens.AccessToken,
		"expires_at":   tokens.ExpiresAt,
	})

	if err != nil {
		logger.Error("Failed to encode response", "error", err.Error())
		SetError(w, err.Error(), http.StatusBadRequest)
	}

	logger.Debug("Login successfully",
		"duration_ms", time.Since(start).Milliseconds(),
		"ip", r.RemoteAddr,
	)
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {

	start := time.Now()
	logger.Debug("Refresh request started", "ip", r.RemoteAddr, "user_agent", r.UserAgent())

	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		logger.Error("Missing refresh token", "error", err.Error())
		SetError(w, ErrMissingRefreshToken, http.StatusUnauthorized)
		return
	}

	tokens, err := h.authService.RefreshAccessToken(r.Context(), cookie.Value)

	if err != nil {
		logger.Error("Failed to refresh token", "error", err.Error())
		SetError(w, ErrInvalidRefreshToken, http.StatusUnauthorized)
		return
	}

	h.setRefreshTokenCookie(w, tokens.RefreshToken)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": tokens.AccessToken,
		"expires_at":   tokens.ExpiresAt,
	})

	if err != nil {
		logger.Error("Failed to encode response", "error", err.Error())
		SetError(w, err.Error(), http.StatusBadRequest)
	}

	logger.Debug("Refresh successfully",
		"duration_ms", time.Since(start).Milliseconds(),
		"ip", r.RemoteAddr,
	)

}

func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req dto.ForgotPasswordRequest

	start := time.Now()
	logger.Debug("ForgotPassword request started", "ip", r.RemoteAddr, "user_agent", r.UserAgent())

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("HTTP ForgotPassword error", "error", err.Error())
		SetError(w, ErrInvalidBody, http.StatusBadRequest)
		return
	}

	if err := h.validate.Struct(req); err != nil {
		SetError(w, ErrInvalidBody, http.StatusBadRequest)
		return
	}

	err := h.authService.VerifyEmail(r.Context(), req.Email)
	if err != nil {
		logger.Error("Failed to verify email", "error", err.Error())
		SetError(w, err.Error(), http.StatusBadRequest)
		return
	}

	token, err := h.authService.GenerateToken()
	if err != nil {
		logger.Error("Failed to generate token", "error", err.Error())
		SetError(w, ErrInternalServer, http.StatusInternalServerError)
		return
	}

	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])

	res, err := h.emailService.Send(r.Context(), &email.EmailRequest{EmailTarget: req.Email,
		MessageText: fmt.Sprintf("http://localhost:5173/reset-password?token=%s", token),
		ContentType: "text/html", Subject: "Reset password"})

	if err != nil {
		logger.Error("Failed to send email", "error", err.Error())
		SetError(w, ErrInternalServer, http.StatusInternalServerError)
		return
	}

	if !res.Success {
		logger.Error("Failed to send email", "error", res.Error)
		SetError(w, ErrInternalServer, http.StatusInternalServerError)
		return
	}

	if err = h.authService.SaveHashToken(r.Context(), req.Email, tokenHash); err != nil {
		logger.Error("Failed to save token", "error", err.Error())
		SetError(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)

	logger.Debug("ForgotPassword successfully",
		"duration_ms", time.Since(start).Milliseconds(),
		"ip", r.RemoteAddr,
	)
}

func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {

	var req dto.ResetPasswordRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SetError(w, ErrInvalidBody, http.StatusBadRequest)
		return
	}

	if err := h.validate.Struct(req); err != nil {
		SetError(w, ErrInvalidBody, http.StatusBadRequest)
		return
	}

	err := h.authService.ResetPassword(r.Context(), req.Token, req.Password)

	if err != nil {
		SetError(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
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
