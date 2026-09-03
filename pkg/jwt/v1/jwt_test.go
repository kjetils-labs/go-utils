package jwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strconv"
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
	manager, err := v1jwt.NewJWTManager(v1jwt.WithSymetricKey(secretKey))
	require.Nilf(t, err, "NewJWTManager should not return an error")

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

// TestJWTManagerRSA tests the RSA functionality of the JWTManager with different key sizes and signing methods.
func TestJWTManagerRSA(t *testing.T) {

	bitSizes := []int{2048, 3072, 4096}
	signingMethods := []jwt.SigningMethod{jwt.SigningMethodRS256, jwt.SigningMethodRS384, jwt.SigningMethodRS512}

	for _, signingMethod := range signingMethods {
		for _, bitSize := range bitSizes {
			name := "RSA_" + strconv.FormatInt(int64(bitSize), 10) + "_" + signingMethod.Alg()
			t.Run(name, func(t *testing.T) {
				privateKey, err := rsa.GenerateKey(nil, bitSize)
				require.Nilf(t, err, "GenerateKey should not return an error")

				manager, err := v1jwt.NewJWTManager(
					v1jwt.WithAsymetricRSAKeys(privateKey, signingMethod),
				)
				require.Nilf(t, err, "NewJWTManager should not return an error")

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
			})
		}
	}

}

func TestJWTManagerECDSA(t *testing.T) {
	ellipticCurves := []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()}
	signingMethods := []jwt.SigningMethod{jwt.SigningMethodES256, jwt.SigningMethodES384, jwt.SigningMethodES512}
	for _, signingMethod := range signingMethods {
		for _, curve := range ellipticCurves {
			name := "ECDSA_" + curve.Params().Name + "_" + signingMethod.Alg()
			t.Run(name, func(t *testing.T) {
				privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
				require.Nilf(t, err, "GenerateKey should not return an error")

				manager, err := v1jwt.NewJWTManager(
					v1jwt.WithAsymetricECDSAKeys(privateKey, signingMethod),
				)
				require.Nilf(t, err, "NewJWTManager should not return an error")

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
			})
		}
	}
}

// TestJWTManagerInvalidToken tests the behavior of the JWTManager when the key is changed.
func TestJWTManagerInvalidKey(t *testing.T) {
	secretKey := []byte("my_secret_key")
	manager, err := v1jwt.NewJWTManager(v1jwt.WithSymetricKey(secretKey))
	require.Nilf(t, err, "NewJWTManager should not return an error")

	claims := jwt.MapClaims{
		"sub":  "1234567890",
		"name": "John Doe",
		"iat":  time.Now().Unix(),
	}
	tokenString, err := manager.CreateToken(t.Context(), claims)
	require.Nilf(t, err, "CreateToken should not return an error")

	// Create a new manager with a different secret key
	newSecretKey := []byte("my_new_secret_key")
	newManager, err := v1jwt.NewJWTManager(v1jwt.WithSymetricKey(newSecretKey))
	require.Nilf(t, err, "NewJWTManager should not return an error")

	parsedClaims := jwt.MapClaims{}
	token, err := newManager.ParseAndValidateToken(t.Context(), tokenString, parsedClaims)
	assert.NotNilf(t, err, "ParseAndValidateToken should return an error for invalid key")
	assert.Nilf(t, token, "Token should be nil for invalid key")
}

// TestJWTManagerInvalidToken tests the behavior of the JWTManager when the token is tampered with.
func TestJWTManagerInvalidToken(t *testing.T) {
	secretKey := []byte("my_secret_key")
	manager, err := v1jwt.NewJWTManager(v1jwt.WithSymetricKey(secretKey))
	require.Nilf(t, err, "NewJWTManager should not return an error")

	claims := jwt.MapClaims{
		"sub":  "1234567890",
		"name": "John Doe",
		"iat":  time.Now().Unix(),
	}
	tokenString, err := manager.CreateToken(t.Context(), claims)
	require.Nilf(t, err, "CreateToken should not return an error")

	// Tamper with the token string to make it invalid
	tamperedTokenString := tokenString + "tampered"

	parsedClaims := jwt.MapClaims{}
	token, err := manager.ParseAndValidateToken(t.Context(), tamperedTokenString, parsedClaims)
	assert.NotNilf(t, err, "ParseAndValidateToken should return an error for tampered token")
	assert.Nilf(t, token, "Token should be nil for tampered token")
}
