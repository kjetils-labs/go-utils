package jwt

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"

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

// ApprovedSigningMethod is a type that represents the approved signing methods for JWT tokens in our implementation.
type ApprovedSigningMethod string

const (

	// HS256 is the HMAC SHA-256 signing method
	// It signs the token using a secret key and is symetrical, meaning the same key is used for both signing and verification.
	HS256 ApprovedSigningMethod = "HS256"

	// RS256 is the RSA SHA-256 signing method
	// It signs the token using a private key and is asymmetrical, meaning a public key is used for verification.
	RS256 ApprovedSigningMethod = "RS256"
)

// ToSigningMethod converts and validates the ApprovedSigningMethod to the corresponding jwt.SigningMethod.
func (m ApprovedSigningMethod) ToSigningMethod() jwt.SigningMethod {
	switch m {
	case HS256:
		return jwt.SigningMethodHS256
	case RS256:
		return jwt.SigningMethodRS256
	default:
		return nil
	}
}

type (
	JWTManager struct {
		secretKey     []byte
		publicKey     *rsa.PublicKey
		privateKey    *rsa.PrivateKey
		signingMethod jwt.SigningMethod
	}

	JWTManagerOptions func(*JWTManager) error
)

func newJWTManager() *JWTManager {
	return &JWTManager{}
}

func WithSecretKey(secretKey []byte) JWTManagerOptions {
	return func(j *JWTManager) error {
		if j.signingMethod != nil {
			return fmt.Errorf("signing method already set, cannot set secret key")
		}
		j.secretKey = secretKey
		j.signingMethod = jwt.SigningMethodHS256

		return nil
	}
}

func WithRSAKeys(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) JWTManagerOptions {
	return func(j *JWTManager) error {
		if j.signingMethod != nil {
			return fmt.Errorf("signing method already set, cannot set RSA keys")
		}
		j.privateKey = privateKey
		j.publicKey = publicKey
		j.signingMethod = jwt.SigningMethodRS256

		return nil
	}
}

// NewJWTManager creates a new JWTManager with the given secret key and signing method.
func NewJWTManager(opts ...JWTManagerOptions) (Manager, error) {
	config := newJWTManager()
	for _, opt := range opts {
		opt(config)
	}

	return config, nil
}

func (j *JWTManager) CreateToken(ctx context.Context, claims jwt.Claims) (string, error) {

	token := jwt.NewWithClaims(j.signingMethod, claims)

	switch j.signingMethod {
	case jwt.SigningMethodHS256:
		tokenString, err := token.SignedString(j.secretKey)
		if err != nil {
			return "", fmt.Errorf("failed to sign token: %w", err)
		}

		return tokenString, nil
	case jwt.SigningMethodRS256:
		tokenString, err := token.SignedString(j.privateKey)
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

		switch j.signingMethod {

		case jwt.SigningMethodHS256:
			return j.secretKey, nil

		case jwt.SigningMethodRS256:
			return j.publicKey, nil

		default:
			return nil, fmt.Errorf("unsupported signing method: %v", j.signingMethod.Alg())
		}
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
