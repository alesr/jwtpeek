package jwtp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func buildHS256Token(t *testing.T, header map[string]any, claims map[string]any, secret string) string {
	t.Helper()

	hdr, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	hdrB64 := base64.RawURLEncoding.EncodeToString(hdr)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := hdrB64 + "." + payloadB64

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + sig
}

func TestDecode(t *testing.T) {
	t.Parallel()

	t.Run("valid token", func(t *testing.T) {
		t.Parallel()
		token := buildHS256Token(t,
			map[string]any{"alg": "HS256", "typ": "JWT"},
			map[string]any{"sub": "1234567890", "name": "John Doe", "iat": 1516239022},
			"secret",
		)

		tok, err := Decode(token)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if tok.Header.Algorithm != "HS256" {
			t.Errorf("expected algorithm HS256, got %s", tok.Header.Algorithm)
		}

		if tok.Header.Type != "JWT" {
			t.Errorf("expected type JWT, got %s", tok.Header.Type)
		}

		if tok.Subject() != "1234567890" {
			t.Errorf("expected subject 1234567890, got %s", tok.Subject())
		}

		name, ok := tok.Claims["name"].(string)
		if !ok || name != "John Doe" {
			t.Errorf("expected name John Doe, got %v", tok.Claims["name"])
		}
	})

	t.Run("malformed token", func(t *testing.T) {
		t.Parallel()

		if _, err := Decode("not-a-valid-token"); err == nil {
			t.Fatal("expected error for malformed token")
		}
	})

	t.Run("empty string", func(t *testing.T) {
		t.Parallel()
		if _, err := Decode(""); err == nil {
			t.Fatal("expected error for empty string")
		}
	})
}

func TestHeader(t *testing.T) {
	t.Parallel()

	t.Run("with key id", func(t *testing.T) {
		t.Parallel()

		token := buildHS256Token(t,
			map[string]any{"alg": "HS256", "typ": "JWT", "kid": "my-key-1"},
			map[string]any{"sub": "user"},
			"secret",
		)

		tok, err := Decode(token)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if tok.Header.KeyID != "my-key-1" {
			t.Errorf("expected kid my-key-1, got %s", tok.Header.KeyID)
		}
	})

	t.Run("raw header contains all fields", func(t *testing.T) {
		token := buildHS256Token(t,
			map[string]any{"alg": "HS256", "typ": "JWT", "kid": "k1", "custom_hdr": "custom_val"},
			map[string]any{"sub": "user"},
			"secret",
		)

		tok, err := Decode(token)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if tok.Header.Raw["custom_hdr"] != "custom_val" {
			t.Errorf("expected custom_hdr in Raw, got %v", tok.Header.Raw)
		}
	})

	t.Run("missing optional fields default to empty", func(t *testing.T) {
		token := buildHS256Token(t,
			map[string]any{"alg": "HS256"},
			map[string]any{"sub": "user"},
			"secret",
		)

		tok, err := Decode(token)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if tok.Header.Type != "" {
			t.Errorf("expected empty type, got %s", tok.Header.Type)
		}

		if tok.Header.KeyID != "" {
			t.Errorf("expected empty kid, got %s", tok.Header.KeyID)
		}

		if tok.Header.ContentType != "" {
			t.Errorf("expected empty cty, got %s", tok.Header.ContentType)
		}
	})
}

func TestStandardClaimAccessors(t *testing.T) {
	t.Parallel()

	now := time.Now()
	iat := now.Add(-1 * time.Hour)
	exp := now.Add(1 * time.Hour)
	nbf := now.Add(-30 * time.Minute)

	token := buildHS256Token(t,
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{
			"iss": "auth.example.com",
			"sub": "user-42",
			"aud": []string{"api.example.com", "admin.example.com"},
			"jti": "unique-id-123",
			"iat": iat.Unix(),
			"exp": exp.Unix(),
			"nbf": nbf.Unix(),
		},
		"secret",
	)

	tok, err := Decode(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Run("issuer", func(t *testing.T) {
		t.Parallel()

		if got := tok.Issuer(); got != "auth.example.com" {
			t.Errorf("expected auth.example.com, got %s", got)
		}
	})

	t.Run("subject", func(t *testing.T) {
		t.Parallel()

		if got := tok.Subject(); got != "user-42" {
			t.Errorf("expected user-42, got %s", got)
		}
	})

	t.Run("audience", func(t *testing.T) {
		t.Parallel()

		aud := tok.Audience()
		if len(aud) != 2 {
			t.Fatalf("expected 2 audiences, got %d", len(aud))
		}
		if aud[0] != "api.example.com" {
			t.Errorf("expected api.example.com, got %s", aud[0])
		}
		if aud[1] != "admin.example.com" {
			t.Errorf("expected admin.example.com, got %s", aud[1])
		}
	})

	t.Run("jwt id", func(t *testing.T) {
		t.Parallel()
		if got := tok.JWTID(); got != "unique-id-123" {
			t.Errorf("expected unique-id-123, got %s", got)
		}
	})

	t.Run("issued at", func(t *testing.T) {
		t.Parallel()

		got := tok.IssuedAt()
		if got == nil {
			t.Fatal("expected non-nil IssuedAt")
		}
		if got.Unix() != iat.Unix() {
			t.Errorf("expected %d, got %d", iat.Unix(), got.Unix())
		}
	})

	t.Run("expires at", func(t *testing.T) {
		t.Parallel()

		got := tok.ExpiresAt()
		if got == nil {
			t.Fatal("expected non-nil ExpiresAt")
		}
		if got.Unix() != exp.Unix() {
			t.Errorf("expected %d, got %d", exp.Unix(), got.Unix())
		}
	})

	t.Run("not before", func(t *testing.T) {
		t.Parallel()

		got := tok.NotBefore()
		if got == nil {
			t.Fatal("expected non-nil NotBefore")
		}
		if got.Unix() != nbf.Unix() {
			t.Errorf("expected %d, got %d", nbf.Unix(), got.Unix())
		}
	})
}

func TestMissingClaimsReturnZeroValues(t *testing.T) {
	t.Parallel()

	token := buildHS256Token(t,
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{}, // empty claims
		"secret",
	)

	tok, err := Decode(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tok.Issuer() != "" {
		t.Errorf("expected empty issuer, got %s", tok.Issuer())
	}

	if tok.Subject() != "" {
		t.Errorf("expected empty subject, got %s", tok.Subject())
	}

	if tok.Audience() != nil {
		t.Errorf("expected nil audience, got %v", tok.Audience())
	}

	if tok.JWTID() != "" {
		t.Errorf("expected empty jti, got %s", tok.JWTID())
	}

	if tok.ExpiresAt() != nil {
		t.Errorf("expected nil ExpiresAt, got %v", tok.ExpiresAt())
	}

	if tok.NotBefore() != nil {
		t.Errorf("expected nil NotBefore, got %v", tok.NotBefore())
	}

	if tok.IssuedAt() != nil {
		t.Errorf("expected nil IssuedAt, got %v", tok.IssuedAt())
	}
}

func TestAudienceSingleString(t *testing.T) {
	t.Parallel()

	token := buildHS256Token(t,
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{"aud": "single-audience"},
		"secret",
	)

	tok, err := Decode(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	aud := tok.Audience()
	if len(aud) != 1 {
		t.Fatalf("expected 1 audience, got %d", len(aud))
	}
	if aud[0] != "single-audience" {
		t.Errorf("expected single-audience, got %s", aud[0])
	}
}

func TestIsExpired(t *testing.T) {
	t.Parallel()

	t.Run("expired token", func(t *testing.T) {
		t.Parallel()

		token := buildHS256Token(t,
			map[string]any{"alg": "HS256", "typ": "JWT"},
			map[string]any{"exp": time.Now().Add(-1 * time.Hour).Unix()},
			"secret",
		)

		tok, err := Decode(token)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !tok.IsExpired() {
			t.Error("expected IsExpired to be true for past expiry")
		}
	})

	t.Run("valid token", func(t *testing.T) {
		t.Parallel()

		token := buildHS256Token(t,
			map[string]any{"alg": "HS256", "typ": "JWT"},
			map[string]any{"exp": time.Now().Add(1 * time.Hour).Unix()},
			"secret",
		)

		tok, err := Decode(token)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if tok.IsExpired() {
			t.Error("expected IsExpired to be false for future expiry")
		}
	})

	t.Run("no exp claim", func(t *testing.T) {
		t.Parallel()

		token := buildHS256Token(t,
			map[string]any{"alg": "HS256", "typ": "JWT"},
			map[string]any{"sub": "user"},
			"secret",
		)

		tok, err := Decode(token)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if tok.IsExpired() {
			t.Error("expected IsExpired to be false when exp is absent")
		}
	})
}

func TestIsNotYetValid(t *testing.T) {
	t.Parallel()

	t.Run("future nbf", func(t *testing.T) {
		t.Parallel()

		token := buildHS256Token(t,
			map[string]any{"alg": "HS256", "typ": "JWT"},
			map[string]any{"nbf": time.Now().Add(1 * time.Hour).Unix()},
			"secret",
		)

		tok, err := Decode(token)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !tok.IsNotYetValid() {
			t.Error("expected IsNotYetValid to be true for future nbf")
		}
	})

	t.Run("past nbf", func(t *testing.T) {
		t.Parallel()

		token := buildHS256Token(t,
			map[string]any{"alg": "HS256", "typ": "JWT"},
			map[string]any{"nbf": time.Now().Add(-1 * time.Hour).Unix()},
			"secret",
		)

		tok, err := Decode(token)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if tok.IsNotYetValid() {
			t.Error("expected IsNotYetValid to be false for past nbf")
		}
	})

	t.Run("no nbf claim", func(t *testing.T) {
		t.Parallel()

		token := buildHS256Token(t,
			map[string]any{"alg": "HS256", "typ": "JWT"},
			map[string]any{"sub": "user"},
			"secret",
		)

		tok, err := Decode(token)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if tok.IsNotYetValid() {
			t.Error("expected IsNotYetValid to be false when nbf is absent")
		}
	})
}

func TestIsActive(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		claims map[string]any
		want   bool
	}{
		{
			name:   "no time claims",
			claims: map[string]any{"sub": "user"},
			want:   true,
		},
		{
			name:   "valid exp and nbf",
			claims: map[string]any{"exp": time.Now().Add(1 * time.Hour).Unix(), "nbf": time.Now().Add(-1 * time.Hour).Unix()},
			want:   true,
		},
		{
			name:   "expired",
			claims: map[string]any{"exp": time.Now().Add(-1 * time.Hour).Unix()},
			want:   false,
		},
		{
			name:   "not yet valid",
			claims: map[string]any{"nbf": time.Now().Add(1 * time.Hour).Unix()},
			want:   false,
		},
		{
			name:   "both expired and not yet valid",
			claims: map[string]any{"exp": time.Now().Add(-1 * time.Hour).Unix(), "nbf": time.Now().Add(1 * time.Hour).Unix()},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			token := buildHS256Token(t,
				map[string]any{"alg": "HS256", "typ": "JWT"},
				tt.claims,
				"secret",
			)

			tok, err := Decode(token)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got := tok.IsActive(); got != tt.want {
				t.Errorf("IsActive() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifyHMAC(t *testing.T) {
	t.Parallel()

	secret := "foo-secret"

	t.Run("valid signature", func(t *testing.T) {
		t.Parallel()

		token := buildHS256Token(t,
			map[string]any{"alg": "HS256", "typ": "JWT"},
			map[string]any{"sub": "user"},
			secret,
		)

		tok, err := Decode(token)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		valid, err := tok.VerifyHMAC(secret)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !valid {
			t.Error("expected signature to be valid")
		}
	})

	t.Run("invalid signature with wrong secret", func(t *testing.T) {
		t.Parallel()

		token := buildHS256Token(t,
			map[string]any{"alg": "HS256", "typ": "JWT"},
			map[string]any{"sub": "user"},
			secret,
		)

		tok, err := Decode(token)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		valid, err := tok.VerifyHMAC("wrong-secret")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if valid {
			t.Error("expected signature to be invalid with wrong secret")
		}
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		t.Parallel()

		token := buildHS256Token(t,
			map[string]any{"alg": "RS256", "typ": "JWT"},
			map[string]any{"sub": "user"},
			secret,
		)

		tok, err := Decode(token)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if _, err = tok.VerifyHMAC(secret); err == nil {
			t.Fatal("expected error for unsupported algorithm")
		}
	})

	t.Run("empty secret", func(t *testing.T) {
		t.Parallel()

		var emptySecret string
		token := buildHS256Token(t,
			map[string]any{"alg": "HS256", "typ": "JWT"},
			map[string]any{"sub": "user"},
			emptySecret,
		)

		tok, err := Decode(token)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		valid, err := tok.VerifyHMAC(emptySecret)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !valid {
			t.Error("expected signature to be valid with matching empty secret")
		}
	})
}

func TestExtraClaimKeys(t *testing.T) {
	t.Parallel()

	token := buildHS256Token(t,
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{
			"iss":   "example.com",
			"sub":   "user",
			"exp":   time.Now().Add(1 * time.Hour).Unix(),
			"role":  "admin",
			"name":  "Alice",
			"email": "alice@example.com",
		},
		"secret",
	)

	tok, err := Decode(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	extra := tok.ExtraClaimKeys()

	expected := []string{"email", "name", "role"}
	if len(extra) != len(expected) {
		t.Fatalf("expected %d extra claims, got %d: %v", len(expected), len(extra), extra)
	}

	for i, key := range expected {
		if extra[i] != key {
			t.Errorf("extra[%d] = %s, want %s", i, extra[i], key)
		}
	}
}

func TestExtraClaimKeysEmpty(t *testing.T) {
	t.Parallel()

	token := buildHS256Token(t,
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{"iss": "example.com", "sub": "user"},
		"secret",
	)

	tok, err := Decode(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	extra := tok.ExtraClaimKeys()
	if len(extra) != 0 {
		t.Errorf("expected no extra claims, got %v", extra)
	}
}

func TestStandardClaimKeys(t *testing.T) {
	t.Parallel()

	keys := StandardClaimKeys()

	expectedKeys := []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti"}
	for _, k := range expectedKeys {
		if _, ok := keys[k]; !ok {
			t.Errorf("expected standard claim key %s to be present", k)
		}
	}
	if len(keys) != len(expectedKeys) {
		t.Errorf("expected %d standard claim keys, got %d", len(expectedKeys), len(keys))
	}
}

func TestIsTimeClaim(t *testing.T) {
	t.Parallel()
	timeClaims := []string{"exp", "nbf", "iat"}
	nonTimeClaims := []string{"iss", "sub", "aud", "jti", "name", "role"}

	for _, k := range timeClaims {
		if !IsTimeClaim(k) {
			t.Errorf("expected %s to be a time claim", k)
		}
	}
	for _, k := range nonTimeClaims {
		if IsTimeClaim(k) {
			t.Errorf("expected %s to NOT be a time claim", k)
		}
	}
}

func TestHeaderLabel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		key  string
		want string
	}{
		{"alg", "Algorithm"},
		{"typ", "Type"},
		{"kid", "Key ID"},
		{"unknown", "unknown"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("key=%s", tt.key), func(t *testing.T) {
			t.Parallel()
			if got := HeaderLabel(tt.key); got != tt.want {
				t.Errorf("HeaderLabel(%s) = %s, want %s", tt.key, got, tt.want)
			}
		})
	}
}

func TestDecodePreservesAllClaims(t *testing.T) {
	t.Parallel()
	claims := map[string]any{
		"iss":          "example.com",
		"sub":          "user-1",
		"custom_bool":  true,
		"custom_num":   float64(42),
		"custom_array": []any{"a", "b", "c"},
		"custom_obj":   map[string]any{"nested": "value"},
	}

	token := buildHS256Token(t,
		map[string]any{"alg": "HS256", "typ": "JWT"},
		claims,
		"secret",
	)

	tok, err := Decode(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(tok.Claims) != len(claims) {
		t.Errorf("expected %d claims, got %d", len(claims), len(tok.Claims))
	}

	if v, ok := tok.Claims["custom_bool"].(bool); !ok || !v {
		t.Errorf("expected custom_bool=true, got %v", tok.Claims["custom_bool"])
	}

	if v, ok := tok.Claims["custom_num"].(float64); !ok || v != 42 {
		t.Errorf("expected custom_num=42, got %v", tok.Claims["custom_num"])
	}

	arr, ok := tok.Claims["custom_array"].([]any)
	if !ok || len(arr) != 3 {
		t.Errorf("expected custom_array with 3 elements, got %v", tok.Claims["custom_array"])
	}

	obj, ok := tok.Claims["custom_obj"].(map[string]any)
	if !ok {
		t.Fatalf("expected custom_obj to be map, got %T", tok.Claims["custom_obj"])
	}
	if obj["nested"] != "value" {
		t.Errorf("expected nested=value, got %v", obj["nested"])
	}
}
