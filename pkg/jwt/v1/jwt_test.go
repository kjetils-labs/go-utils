package jwt_test

import (
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	v1jwt "github.com/kjetils-labs/go-utils/pkg/jwt/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestJWTManagerHMARC tests the HMARC functionality of the JWTManager.
func TestJWTManagerHMARC(t *testing.T) {
	secretKey := []byte("my_secret_key")
	manager, err := v1jwt.NewJWTManager(v1jwt.WithSecretKey(secretKey))
	require.Nilf(t, err, "NewJWTManager should not return an error")

	// Create a token
	claims := jwt.MapClaims{
		"sub":  "1234567890",
		"name": "John Doe",
		"iat":  time.Now().Unix(),
	}
	tokenString, err := manager.CreateToken(t.Context(), claims)
	require.Nilf(t, err, "CreateToken should not return an error")

	parsedClaims := jwt.MapClaims{}
	token, err := manager.ParseAndValidateToken(t.Context(), tokenString, parsedClaims)
	assert.Nilf(t, err, "ParseAndValidateToken should not return an error")
	assert.Truef(t, token.Valid, "Token should be valid")

}

func TestJWTManagerRSA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(nil, 2048)
	require.Nilf(t, err, "GenerateKey should not return an error")

	manager, err := v1jwt.NewJWTManager(
		v1jwt.WithRSAKeys(privateKey, &privateKey.PublicKey),
	)
	require.Nilf(t, err, "NewJWTManager should not return an error")

	// Create a token
	claims := jwt.MapClaims{
		"sub":  "1234567890",
		"name": "John Doe",
		"iat":  time.Now().Unix(),
	}
	tokenString, err := manager.CreateToken(t.Context(), claims)
	require.Nilf(t, err, "CreateToken should not return an error")

	parsedClaims := jwt.MapClaims{}
	token, err := manager.ParseAndValidateToken(t.Context(), tokenString, parsedClaims)
	assert.Nilf(t, err, "ParseAndValidateToken should not return an error")
	assert.Truef(t, token.Valid, "Token should be valid")
}
