# LocalScale control plane

First vertical slice for the LocalScale control plane. This crate intentionally uses only the Rust standard library, so it has no external dependency or credential requirement.

## Included

- Deterministic `health()` and `version()` library handlers.
- In-memory organizations, users, and devices.
- Registration contracts that accept device public keys only and reject private-key material.
- Organization authorization with deny-by-default behavior.
- `FakeOidcVerifier`, a legacy deterministic verifier seam retained for existing callers; it performs no network calls.
- `google_oidc`, a network-independent Authorization Code + PKCE core: validated environment/config inputs, OS-random single-use transactions, S256 authorization URLs, callback transaction consumption, and claim validation.

The OIDC core deliberately does not fetch discovery metadata, exchange codes, verify JWT signatures, parse Google client-secret JSON, or provide a fake successful login. An HTTP/token adapter must perform those operations and inject only an opaque `ClientSecretRef`. `base64`, `sha2`, `rand`, and `form_urlencoded` are pinned mature crates used for URL-safe randomness, S256, and standards-compliant query encoding; no secret is serializable or included in URLs/debug output.

This is a library slice, not an HTTP server. No Google credentials, Tor integration, or data-plane networking are implemented.

## Future Google/OIDC integration

A future HTTP adapter may expose endpoints such as:

- `GET /healthz`
- `GET /version`
- `POST /v1/organizations`
- `POST /v1/organizations/{organization_id}/users`
- `POST /v1/organizations/{organization_id}/devices` (public key only)
- `GET /v1/organizations/{organization_id}/authorize`
- `GET /oauth/google/start`
- `GET /oauth/google/callback`

The eventual Google-backed adapter should read configuration from environment variables (names are placeholders and carry no secrets here):

- `LOCALSCALE_OIDC_ISSUER`
- `LOCALSCALE_OIDC_AUDIENCE`
- `LOCALSCALE_GOOGLE_CLIENT_ID`
- `LOCALSCALE_GOOGLE_CLIENT_SECRET`
- `LOCALSCALE_GOOGLE_REDIRECT_URI`

The real Phase 1 core is network-independent and is intended to be wrapped by the future HTTP adapter. That adapter must supply discovery/JWKS and token exchange; the core does not read `LOCALSCALE_GOOGLE_CLIENT_SECRET` or any Google JSON file. `GoogleOidcConfig::from_env` reads issuer, audience (or client ID), exact redirect URI, and optional whitespace-separated scopes, while the secret remains an injected `ClientSecretRef`.

## Verification

From this directory:

```text
cargo test
cargo build
```
