package http

import "context"

// GetClaimsFromContext retrieves the JWT claims from the provided context if they exist.
// It returns the claims as a map and a boolean indicating whether the claims were found.
func GetClaimsFromContext(ctx context.Context) (map[string]interface{}, bool) {
	claims, ok := ctx.Value("claims").(map[string]interface{})
	return claims, ok
}
