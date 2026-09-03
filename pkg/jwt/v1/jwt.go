package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	httphelper "github.com/kjetils-labs/go-utils/pkg/http/v1"
)

// Guard caluse to ensure that JWTManager implements the Manager interface at compile time.
var _ Manager = (*JWTManager)(nil)

// Manager is an interface that defines methods for creating and validating JWT tokens.
type Manager interface {

	// CreateToken creates a new JWT token with the given claims and returns the token string.
	CreateToken(Ctx context.Context, claims jwt.Claims) (string, error)

	// ParseAndValidateToken parses and validates the given JWT token string and returns the token if valid.
	ParseAndValidateToken(Ctx context.Context, tokenString string, claims jwt.Claims) (*jwt.Token, error)
}

type (
	JWTManager struct {
		secretKey     []byte
		rsaPrivateKey *rsa.PrivateKey
		esPrivateKey  *ecdsa.PrivateKey
		signingMethod jwt.SigningMethod
		symmetric     bool
	}

	JWTManagerOptions func(*JWTManager) error
)

func newJWTManager() *JWTManager {
	return &JWTManager{
		secretKey:     nil,
		rsaPrivateKey: nil,
		esPrivateKey:  nil,
		signingMethod: nil,
		symmetric:     false,
	}
}

func WithSymetricKey(secretKey []byte) JWTManagerOptions {
	return func(j *JWTManager) error {
		if j.signingMethod != nil {
			return fmt.Errorf("signing method already set, cannot set secret key")
		}
		j.secretKey = secretKey
		j.signingMethod = jwt.SigningMethodHS256
		j.symmetric = true

		return nil
	}
}

// WithAsymetricRSAKeys sets the private and public keys for the JWTManager, along with the signing method.
// Expected signing methods of the RS family, e.g. RS256, RS384, RS512, PS256, PS384, PS512.
func WithAsymetricRSAKeys(privateKey *rsa.PrivateKey, signingMethod jwt.SigningMethod) JWTManagerOptions {
	return func(j *JWTManager) error {
		if j.signingMethod != nil {
			return fmt.Errorf("signing method already set, cannot set public/private key pair")
		}

		j.rsaPrivateKey = privateKey
		j.signingMethod = signingMethod
		j.symmetric = false

		return nil
	}
}

func WithAsymetricECDSAKeys(privateKey *ecdsa.PrivateKey, signingMethod jwt.SigningMethod) JWTManagerOptions {
	return func(j *JWTManager) error {
		if j.signingMethod != nil {
			return fmt.Errorf("signing method already set, cannot set public/private key pair")
		}

		j.esPrivateKey = privateKey
		j.signingMethod = signingMethod
		j.symmetric = false

		return nil
	}
}

// NewJWTManager creates a new JWTManager with the given secret key and signing method.
func NewJWTManager(opts ...JWTManagerOptions) (Manager, error) {
	config := newJWTManager()
	for _, opt := range opts {
		err := opt(config)
		if err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}

	return config, nil
}

func (j *JWTManager) CreateToken(ctx context.Context, claims jwt.Claims) (string, error) {

	token := jwt.NewWithClaims(j.signingMethod, claims)

	switch {
	case strings.HasPrefix(j.signingMethod.Alg(), "HS"):
		tokenString, err := token.SignedString(j.secretKey)
		if err != nil {
			return "", fmt.Errorf("failed to sign token: %w", err)
		}

		return tokenString, nil
	case strings.HasPrefix(j.signingMethod.Alg(), "RS"):
		tokenString, err := token.SignedString(j.rsaPrivateKey)
		if err != nil {
			return "", fmt.Errorf("failed to sign token: %w", err)
		}

		return tokenString, nil
	case strings.HasPrefix(j.signingMethod.Alg(), "ES"):
		tokenString, err := token.SignedString(j.esPrivateKey)
		if err != nil {
			return "", fmt.Errorf("failed to sign token: %w", err)
		}

		return tokenString, nil

	default:
		return "", fmt.Errorf("unsupported signing method: %v", j.signingMethod.Alg())
	}

}

func (j *JWTManager) ParseAndValidateToken(_ context.Context, tokenString string, claims jwt.Claims) (*jwt.Token, error) {

	keyFunc := func(token *jwt.Token) (any, error) {

		// We make sure the signing method configured matches the signing method used on the token.
		if token.Method.Alg() != j.signingMethod.Alg() {
			return nil, fmt.Errorf("unexpected token signing method: %v, expected %v", token.Method.Alg(), j.signingMethod)
		}

		if j.symmetric {
			return j.secretKey, nil
		}

		if j.rsaPrivateKey != nil {
			return &j.rsaPrivateKey.PublicKey, nil
		}

		if j.esPrivateKey != nil {
			return &j.esPrivateKey.PublicKey, nil
		}

		return nil, fmt.Errorf("no valid key found for signing method: %v", j.signingMethod)

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

// AuthenticationMiddleware is a middleware function that checks for the presence of a valid JWT token in the Authorization header of incoming HTTP requests.
//
// If HS256 is used as the signing method, it expects the the signing secret to verify the token.
// If RS256 is used as the signing method, it expects the public key to verify the token.
func (j *JWTManager) AuthenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			httphelper.WriteJSONError(w, "Missing token", http.StatusUnauthorized)
			return
		}

		claims := &jwt.MapClaims{}
		token, err := j.ParseAndValidateToken(r.Context(), tokenString, claims)
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
