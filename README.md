# jwtpeek

[![Go Reference](https://pkg.go.dev/badge/github.com/alesr/jwtpeek.svg)](https://pkg.go.dev/github.com/alesr/jwtpeek)
[![codecov](https://codecov.io/gh/alesr/jwtpeek/graph/badge.svg?token=7QYM4Yfupt)](https://codecov.io/gh/alesr/jwtpeek)

Decode and verify JWT tokens in Go.

## CLI

```
go install github.com/alesr/jwtpeek/cmd/jwtpeek@latest
```

```
jwtpeek -token eyJhbGciOiJIUzI1NiIs...
```

Decode and verify the signature (if you have the secret):

```
~ ❱ jwtpeek -token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30 -secret a-string-secret-at-least-256-bits-long
── HEADER ──────────────────────────────────
  Algorithm        HS256
  Type             JWT

── PAYLOAD ──────────────────────────────────
  Subject          1234567890
  Issued At        2018-01-18T01:30:22Z (8 years ago)
  ────────────────────────────────────
  admin            true
  name             John Doe

── STATUS ──────────────────────────────────
  ✓ Structure      Valid JWT with 3 parts
  ✓ Algorithm      HS256
  ✓ Issued At      Issued 8 years ago
  ⚠ Expiration     No 'exp' claim present
  ✓ Signature      Valid (verified with provided secret)
```

## Library

```
go get github.com/alesr/jwtpeek
```

```go
tok, err := jwtpeek.Decode(rawToken)
if err != nil {
    // malformed token
}

tok.Subject()   // "user-123"
tok.IsExpired() // true
tok.IsActive()  // not expired and nbf has passed

valid, err := tok.VerifyHMAC("my-secret") // HS256, HS384, HS512
```

All claims are also available as a raw map via `tok.Claims`.

## Development

The library and CLI are separate Go modules. After cloning, set up a workspace so the CLI picks up the local library:

```
go work init . ./cmd/jwtpeek
```
