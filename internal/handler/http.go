package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/space-event/auth-service/internal/service"
	"github.com/space-event/auth-service/pkg/dto"
	email "github.com/space-event/email-service/pkg/emailpb"
)

type AuthHandler struct {
	authService  *service.AuthService
	emailService email.EmailServiceClient
}

func NewAuthHandler(authService *service.AuthService, emailService email.EmailServiceClient) *AuthHandler {
	return &AuthHandler{authService: authService, emailService: emailService}
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

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SetError(w, "invalid body", http.StatusBadRequest)
		return
	}

	tokens, err := h.authService.Register(r.Context(), req)

	if err != nil {
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
		SetError(w, err.Error(), http.StatusBadRequest)
		return
	}
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req dto.LoginRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SetError(w, "invalid body", http.StatusBadRequest)
		return
	}

	tokens, err := h.authService.Login(r.Context(), req)

	if err != nil {
		log.Printf("Registration error: %v", err)
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
		log.Printf("json encode error: %v", err)
		SetError(w, err.Error(), http.StatusBadRequest)
	}
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		SetError(w, "missing refresh token", http.StatusUnauthorized)
		return
	}

	tokens, err := h.authService.RefreshAccessToken(r.Context(), cookie.Value)

	if err != nil {
		SetError(w, "invalid refresh token", http.StatusUnauthorized)
		log.Fatalf("Error: %v", err.Error())
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
		log.Printf("json encode error: %v", err)
		SetError(w, err.Error(), http.StatusBadRequest)
	}

}

func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req dto.ForgotPasswordRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SetError(w, "Invalid body", http.StatusBadRequest)
		return
	}

	log.Println(req)

	err := h.authService.VerifyEmail(r.Context(), req.Email)
	if err != nil {
		SetError(w, err.Error(), http.StatusBadRequest)
		return
	}

	token, err := h.authService.GenerateToken()
	if err != nil {
		SetError(w, "Something went wrong", http.StatusBadRequest)
		return
	}

	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])

	log.Printf("Token hash: %s", tokenHash)

	res, err := h.emailService.Send(r.Context(), &email.EmailRequest{EmailTarget: req.Email,
		MessageText: fmt.Sprintf("http://localhost:5173/reset-password?token=%s", token),
		ContentType: "text/html", Subject: "Reset password"})

	if err != nil {
		SetError(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Println(res)
	if !res.Success {
		SetError(w, res.Error, http.StatusBadRequest)
		return
	}

	if err = h.authService.SaveHashToken(r.Context(), req.Email, tokenHash); err != nil {
		SetError(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {

	var req dto.ResetPasswordRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SetError(w, "invalid body", http.StatusBadRequest)
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
