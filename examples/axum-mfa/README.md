# axum-mfa

The TOTP multi-factor lifecycle on top of the minimal service: `setup` (the secret
and `otpauth://` URI are returned **once**), `verify-enable`, and the temp-token
`challenge`. After MFA is enabled, `login` returns `{ mfaRequired: true, mfaTempToken }`
and the client completes the challenge to finish signing in.

## Run

```bash
cargo run -p axum-mfa
# listens on 127.0.0.1:8081 (override with BIND_ADDR)
```

1. Register and log in (as in `axum-minimal`).
2. `POST /auth/mfa/setup` (authenticated) → store the returned secret in an
   authenticator app; the `otpauth://` URI renders as a QR code.
3. `POST /auth/mfa/verify-enable` with a current 6-digit code → MFA is on.
4. Subsequent `login` returns an `mfaTempToken`; `POST /auth/mfa/challenge` with the
   temp token + a code returns the real tokens.

The MFA secret-at-rest key is AES-256-GCM (32 bytes, base64). This example uses a
fixed placeholder for clarity — generate a fresh random key per deployment and load
it from a secret manager.
