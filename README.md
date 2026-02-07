# jwtp

Decode and verify JWT tokens in Go.

## CLI

```
go install github.com/alesr/jwtp/cmd/jwtp@latest
```

```
jwtp -token eyJhbGciOiJIUzI1NiIs...
```

Verify the signature if you have the secret:

```
jwtp -token eyJhbGciOiJIUzI1NiIs... -secret your-secret
```

You get the header, payload with human-readable timestamps, and a status section telling you if the token is expired, not yet valid, and whether the signature checks out.

## Library

```
go get github.com/alesr/jwtp
```

```go
tok, err := jwtp.Decode(rawToken)
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
go work init . ./cmd/jwtp
```
