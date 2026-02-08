// Package jwtpeek provides JWT token decoding, inspection, and validation
// without requiring the signing key upfront.
//
// Tokens are decoded without signature verification by default.
// Signature verification can be performed separately via [Token.VerifyHMAC].
package jwtpeek

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"sort"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Header represents the JOSE header of a JWT.
type Header struct {
	Algorithm   string
	Type        string
	KeyID       string
	ContentType string
	Raw         map[string]any
}

// Token represents a decoded JWT.
type Token struct {
	Header Header
	// standard claims (iss, sub, aud, exp, nbf, iat, jti)
	// can also be accessed via typed convenience methods
	Claims map[string]any
	parts  []string // for signature verification
}

// Decode parses a JWT token string without verifying its signature.
// It returns the fully decoded [Token] or an error if the token is malformed.
func Decode(tokenString string) (*Token, error) {
	parser := jwt.NewParser()

	parsed, parts, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("could not parse token: %w", err)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected claims type: %T", parsed.Claims)
	}

	header := Header{
		Algorithm: stringFromHeader(parsed.Header, "alg"),
		Type:      stringFromHeader(parsed.Header, "typ"),
		KeyID:     stringFromHeader(parsed.Header, "kid"),
		Raw:       parsed.Header,
	}

	if cty, ok := parsed.Header["cty"].(string); ok {
		header.ContentType = cty
	}
	return &Token{
		Header: header,
		Claims: map[string]any(claims),
		parts:  parts,
	}, nil
}

// Issuer returns the "iss" claim value.
func (t *Token) Issuer() string { return stringClaim(t.Claims, "iss") }

// Subject returns the "sub" claim value.
func (t *Token) Subject() string { return stringClaim(t.Claims, "sub") }

// JWTID returns the "jti" claim value.
func (t *Token) JWTID() string { return stringClaim(t.Claims, "jti") }

// ExpiresAt returns the "exp" claim as a [time.Time].
func (t *Token) ExpiresAt() *time.Time { return timeClaim(t.Claims, "exp") }

// NotBefore returns the "nbf" claim as a [time.Time].
func (t *Token) NotBefore() *time.Time { return timeClaim(t.Claims, "nbf") }

// IssuedAt returns the "iat" claim as a [time.Time].
func (t *Token) IssuedAt() *time.Time { return timeClaim(t.Claims, "iat") }

// Audience returns the "aud" claim value as a string slice.
func (t *Token) Audience() []string {
	val, exists := t.Claims["aud"]
	if !exists {
		return nil
	}

	switch v := val.(type) {
	case string:
		return []string{v}
	case []any:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	case []string:
		return v
	default:
		return nil
	}
}

// IsExpired reports whether the token has an "exp" claim that is in the past.
func (t *Token) IsExpired() bool {
	exp := t.ExpiresAt()
	if exp == nil {
		return false
	}
	return time.Now().After(*exp)
}

// IsNotYetValid reports whether the token has an "nbf" claim that is in the future.
func (t *Token) IsNotYetValid() bool {
	nbf := t.NotBefore()
	if nbf == nil {
		return false
	}
	return time.Now().Before(*nbf)
}

// IsActive reports whether the token is currently usable:
// it is not expired and its "not before" time (if present) has passed.
func (t *Token) IsActive() bool { return !t.IsExpired() && !t.IsNotYetValid() }

// VerifyHMAC verifies the token signature using the given HMAC secret.
// It supports HS256, HS384, and HS512 algorithms.
// Returns true if the signature is valid, false otherwise.
// Error only if the algorithm is unsupported for HMAC verification.
func (t *Token) VerifyHMAC(secret string) (bool, error) {
	if len(t.parts) != 3 {
		return false, fmt.Errorf("could not validate token structure: expected 3 parts, got %d", len(t.parts))
	}

	var hashFunc func() hash.Hash

	switch t.Header.Algorithm {
	case "HS256":
		hashFunc = sha256.New
	case "HS384":
		hashFunc = sha512.New384
	case "HS512":
		hashFunc = sha512.New
	default:
		return false, fmt.Errorf("unsupported algorithm for HMAC verification: %s", t.Header.Algorithm)
	}

	signingInput := t.parts[0] + "." + t.parts[1]

	mac := hmac.New(hashFunc, []byte(secret))
	mac.Write([]byte(signingInput))
	expectedSig := mac.Sum(nil)

	actualSig, err := base64.RawURLEncoding.DecodeString(t.parts[2])
	if err != nil {
		return false, fmt.Errorf("could not decode signature: %w", err)
	}
	return hmac.Equal(expectedSig, actualSig), nil
}

// StandardClaimKeys returns the set of registered JWT claim names as defined in RFC 7519 Section 4.1.
func StandardClaimKeys() map[string]string {
	return map[string]string{
		"iss": "Issuer",
		"sub": "Subject",
		"aud": "Audience",
		"exp": "Expires At",
		"nbf": "Not Before",
		"iat": "Issued At",
		"jti": "JWT ID",
	}
}

// IsTimeClaim reports whether the given claim key is a registered time-based claim (exp, nbf, or iat).
func IsTimeClaim(key string) bool {
	switch key {
	case "exp", "nbf", "iat":
		return true
	default:
		return false
	}
}

// HeaderLabel returns a human-readable label for known JOSE header parameters.
// For unrecognized keys it returns the key itself.
func HeaderLabel(key string) string {
	labels := map[string]string{
		"alg": "Algorithm",
		"typ": "Type",
		"kid": "Key ID",
		"jku": "JWK Set URL",
		"x5u": "X.509 URL",
		"x5c": "X.509 Chain",
		"cty": "Content Type",
	}
	if label, ok := labels[key]; ok {
		return label
	}
	return key
}

// ExtraClaimKeys returns claim keys that are not part of the standard
// registered set, sorted alphabetically.
func (t *Token) ExtraClaimKeys() []string {
	std := StandardClaimKeys()
	var extra []string
	for k := range t.Claims {
		if _, isStd := std[k]; !isStd {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	return extra
}

func stringFromHeader(h map[string]any, key string) string {
	if v, ok := h[key].(string); ok {
		return v
	}
	return ""
}

func stringClaim(claims map[string]any, key string) string {
	if v, ok := claims[key].(string); ok {
		return v
	}
	return ""
}

func timeClaim(claims map[string]any, key string) *time.Time {
	val, exists := claims[key]
	if !exists {
		return nil
	}

	var ts float64
	switch v := val.(type) {
	case float64:
		ts = v
	case json.Number:
		f, err := v.Float64()
		if err != nil {
			return nil
		}
		ts = f
	default:
		return nil
	}
	t := time.Unix(int64(ts), 0).UTC()
	return &t
}
