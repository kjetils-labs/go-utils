package http

import (
	"context"
	"fmt"
	"slices"
)

type contextKey string

const ClaimsContextKey contextKey = "claims"

var (
	ErrClaimsNotFound    = fmt.Errorf("claims not found in context")
	ErrParameterNotFound = fmt.Errorf("parameter not found in claims")
	ErrGroupsNotFound    = fmt.Errorf("groups not found in claims")
	ErrInvalidGroupsType = fmt.Errorf("invalid type for groups in claims")
	ErrNoMatchingGroup   = fmt.Errorf("no matching group found in claims")
)

// GetClaimsFromContext retrieves the claims from the context.
func GetClaimsFromContext(ctx context.Context) (map[string]any, error) {
	claims, ok := ctx.Value(ClaimsContextKey).(map[string]any)
	if !ok {
		return nil, ErrClaimsNotFound
	}
	return claims, nil
}

// IsParameterInClaim checks if a specific parameter exists in the claims.
func IsParameterInClaim(ctx context.Context, key string) (any, error) {
	claims, err := GetClaimsFromContext(ctx)
	if err != nil {
		return nil, err
	}

	val, ok := claims[key]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrParameterNotFound, key)
	}
	return val, nil
}

// IsGroupInClaim checks if a specific group exists in the claims.
func IsGroupInClaim(ctx context.Context, group string) (string, error) {
	aClaimpGroups, err := IsParameterInClaim(ctx, "groups")
	if err != nil {
		return "", err
	}

	claimGroups := castSliceToStringSlice(aClaimpGroups.([]any))

	for _, g := range claimGroups {
		if g == group {
			return g, nil
		}
	}

	return "", ErrNoMatchingGroup
}

// isAGroupinClaim checks if any of the specified groups exist in the claims.
func IsAGroupInClaim(ctx context.Context, groups []string) (string, error) {
	aClaimGroups, err := IsParameterInClaim(ctx, "groups")
	if err != nil {
		return "", err
	}

	claimGroups := castSliceToStringSlice(aClaimGroups.([]any))

	for _, g := range claimGroups {
		if slices.Contains(groups, g) {
			return g, nil
		}
	}

	return "", ErrNoMatchingGroup
}

func castSliceToStringSlice[T any](input []T) []string {
	result := make([]string, len(input))
	for i, v := range input {
		result[i] = fmt.Sprintf("%v", v)
	}
	return result
}
