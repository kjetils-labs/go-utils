package jwt

import (
	"context"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v4"
	httphelper "github.com/kjetils-labs/go-utils/pkg/http/v1"
)

// Ensure that JWTManager implements the Manager interface
var _ Manager = (*JWTManager)(nil)

type Manager interface {
	CreateToken(Ctx context.Context, claims jwt.Claims) (string, error)

	ParseAndValidateToken(Ctx context.Context, tokenString string, claims jwt.Claims) (*jwt.Token, error)
}

type JWTManager struct {
	secretKey []byte
}

func NewJWTManager(secretKey []byte) Manager {
	return &JWTManager{
		secretKey: secretKey,
	}
}

type LoginResponse struct {
	Token string `json:"token"`
}

func NewLoginResponse(token string) *LoginResponse {
	return &LoginResponse{
		Token: token,
	}
}

func (j *JWTManager) CreateToken(ctx context.Context, claims jwt.Claims) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		claims)

	tokenString, err := token.SignedString(j.secretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (j *JWTManager) ParseAndValidateToken(_ context.Context, tokenString string, claims jwt.Claims) (*jwt.Token, error) {

	keyFunc := func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.secretKey, nil
	}

	token, err := jwt.ParseWithClaims(tokenString, claims, keyFunc)
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return token, nil
}

func AuthenticationMiddleware(next http.Handler, secret string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			httphelper.WriteJSONError(w, "Missing token", http.StatusUnauthorized)
			return
		}

		manager := NewJWTManager([]byte(secret))

		claims := &jwt.MapClaims{}
		token, err := manager.ParseAndValidateToken(r.Context(), tokenString, claims)
		if err != nil {
			httphelper.WriteJSONError(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		if !token.Valid {
			httphelper.WriteJSONError(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}
