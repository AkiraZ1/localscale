# LocalScale Google SSO runbook

This runbook configures Google OpenID Connect (OIDC) for LocalScale. It does not create credentials. A deployment operator must perform the console steps and place the resulting client ID/secret in the deployment's secret store.

## Boundary and modes

- **Host mode:** the LocalScale Host runs the control plane and starts the local web page automatically. The browser is the user agent; the Host owns the authorization-code exchange and never sends a client secret to the page.
- **Cliente mode:** the Cliente opens the Host-provided/local web page for pairing and operation. It does not receive a Google client secret and does not implement a second Google login. The Host's authenticated session and explicit authorization determine which Cliente actions are accepted.
- **Onion/public access:** an Onion URL is a transport endpoint, not an identity boundary. If a Host is reachable through Onion, use the production/staging HTTPS callback only when the callback is served by the control plane under that exact origin; never register a wildcard or an arbitrary `.onion` callback.

The recommended architecture is one confidential web client per environment (local, staging, production), with the Host handling OIDC and the browser holding only an HttpOnly session cookie.

## Google Cloud Console URLs

Select the intended project before using any project-scoped page. These are exact Google Cloud Console routes:

- Project selector / create or select a project: <https://console.cloud.google.com/projectselector/home/dashboard>
- Project settings: <https://console.cloud.google.com/iam-admin/settings>
- Google Auth Platform Branding: <https://console.cloud.google.com/auth/branding>
- Google Auth Platform Audience: <https://console.cloud.google.com/auth/audience>
- Google Auth Platform Data Access: <https://console.cloud.google.com/auth/scopes>
- Google Auth Platform Clients: <https://console.cloud.google.com/auth/clients>
- APIs & Services credentials (fallback/view-only location): <https://console.cloud.google.com/apis/credentials>
- OAuth consent-screen legacy route (may redirect to Auth Platform): <https://console.cloud.google.com/apis/credentials/consent>

Google may redirect these routes to a sign-in page or append `project`/`authuser` parameters. That is expected; do not treat a redirect as a different application route.

## One-time project setup

1. Open the [project selector](https://console.cloud.google.com/projectselector/home/dashboard), create or select a dedicated Google Cloud project named for the LocalScale environment, and record its project ID. Do not use a personal or unrelated project.
2. Open [Project settings](https://console.cloud.google.com/iam-admin/settings) and verify the project ID and organization. Restrict project administration to the smallest operator group.
3. Open [Branding](https://console.cloud.google.com/auth/branding) and choose **Get started** if the project has no Google Auth Platform configuration.
4. In **App information**, set the application name to **LocalScale**, add the approved user-support email, and add the authorized application home page/privacy-policy links required by the selected audience. Keep all text LocalScale-specific.
5. In **Audience** (either the next page or [Audience](https://console.cloud.google.com/auth/audience)), choose **Internal** when every user is in the owning Google Workspace organization. Choose **External** only when LocalScale must accept consumer or other-organization Google accounts. For External, add the operator accounts under **Test users** before testing.
6. In **Contact information**, enter the monitored security/operations address and finish the Google API Services User Data Policy acknowledgement. Save the configuration.

### Data Access / scopes

Open [Data Access](https://console.cloud.google.com/auth/scopes), select **Add or remove scopes**, and request the minimum set:

- `openid` — OIDC identity and ID token.
- `email` — email and `email_verified` for display/contact and initial authorization policy.
- `profile` — optional basic display name/profile data; omit it if LocalScale does not need it.

LocalScale SSO must not request Google API scopes (Drive, Gmail, Calendar, or broad cloud scopes) unless a separately reviewed feature explicitly needs them. Save and review the final scope list. An External app needing sensitive/restricted scopes may require Google's verification; SSO with only `openid email profile` is the preferred starting point.

### Clients

1. Open [Clients](https://console.cloud.google.com/auth/clients) and choose **Create client**. If the page offers only the legacy flow, use **APIs & Services → Credentials → Create credentials → OAuth client ID** at [Credentials](https://console.cloud.google.com/apis/credentials).
2. Select **Web application**. Create separate clients named `LocalScale local`, `LocalScale staging`, and `LocalScale production`; do not reuse a production secret in local development.
3. Add only the exact redirect URI(s) for that client from the table below. Leave **Authorized JavaScript origins** empty unless a future design deliberately performs browser-side OAuth; the Host-server exchange does not need them.
4. Create the client, record the client ID, and transfer the secret directly to the approved secret store. Do not paste it into source, Markdown, issue trackers, chat, browser code, or logs.

## Redirect URI strategy

Google matches redirect URIs exactly. Scheme, host, port, path, case, and trailing slash must match the value sent in the authorization request.

| Environment | Canonical callback | Registration policy |
|---|---|---|
| Local Host | `http://127.0.0.1:<PORT>/auth/google/callback` | Register the actual configured loopback port for the local web page. Prefer a fixed documented port; if the port is dynamic, create the local client entry per chosen port before testing. Do not use a LAN address. |
| Staging Host | `https://staging.<approved-local-scale-domain>/auth/google/callback` | Use the staging hostname and HTTPS certificate. Register no production or localhost callback on this client. |
| Production Host | `https://<approved-local-scale-domain>/auth/google/callback` | Use the one canonical HTTPS origin. If an Onion service is supported, it must not silently change the callback origin; route the browser back through this canonical HTTPS endpoint or obtain a separately reviewed client and exact callback. |

Replace placeholders with the deployment's approved values before entering them in Google. Do not register `*`, query-string variants, fragments, arbitrary subdomains, `http://0.0.0.0`, or an Onion hostname as a convenience. The automatic local-page startup must print/open the same local callback origin that the Host configured; if startup chooses a different port, fail closed rather than falling back to a broad URI.

## OIDC authorization contract

Use Google's discovery document at <https://accounts.google.com/.well-known/openid-configuration> at runtime/startup (with safe caching), rather than hard-coding signing keys. The normal flow is Authorization Code + PKCE:

1. Host creates a cryptographically random, single-use `state`, `nonce`, and PKCE `code_verifier`; retain them server-side or in a short-lived, SameSite session transaction bound to the browser. Store the intended post-login path as server-side data, not as an unvalidated redirect URL.
2. Host redirects the browser to the discovered authorization endpoint with `client_id`, exact `redirect_uri`, `response_type=code`, `scope=openid email profile` (remove `profile` if unused), `state`, `nonce`, `code_challenge`, and `code_challenge_method=S256`.
3. Callback accepts only an expected `code` and exact `state`; reject missing, reused, expired, or mismatched transactions. Do not accept an ID token in a URL fragment or authorize from email alone.
4. Host exchanges the code at the discovered token endpoint with the same `redirect_uri`, the `code_verifier`, client ID, and client secret. Keep the authorization code and tokens off the page URL and logs.
5. Validate the ID token signature using the discovery `jwks_uri`, then validate `iss` (`https://accounts.google.com` or the documented legacy issuer form), `aud` (this client ID), `exp`, `iat`/reasonable clock skew, and the exact one-time `nonce`. Validate `email_verified` before using email in policy.
6. Use `sub` as the stable Google subject key; email is mutable and is not the primary identity key. Apply LocalScale authorization separately (Host owner/admin/operator policy), then issue a short-lived, Secure, HttpOnly, SameSite session cookie.

### Claims to retain and use

Required/important ID-token claims: `iss`, `sub`, `aud`, `exp`, and `iat`; verify `nonce`. Use `email` only with `email_verified=true` and treat `name`, `picture`, and `locale` as optional display data. Ignore unrecognized claims. Do not use `hd` as proof of identity or authorization; if Workspace restriction is required, enforce an explicit allowlist/policy after normal issuer, audience, signature, and subject validation.

## Test users and acceptance test

For an External audience, add only approved test accounts in [Audience → Test users](https://console.cloud.google.com/auth/audience). Use named test accounts, not shared credentials. Test each environment separately:

- automatic Host startup opens the expected local page and exact loopback callback;
- successful login returns to the LocalScale page, creates one Host session, and exposes the correct Host/Cliente mode;
- a second tab with a mismatched state fails without creating a session;
- a changed redirect URI, issuer, audience, nonce, expired token, or unverified email is rejected;
- Cliente requests cannot substitute their own user ID or bypass Host authorization;
- logout clears the LocalScale session and does not imply Google logout;
- the Onion route cannot downgrade TLS policy, alter the callback, or bypass Host authorization.

Record results without recording tokens, codes, cookies, or secrets. Before production, remove temporary test users that are not approved for ongoing testing and complete any Google verification required for the final scope/audience.

## Secret handling, logout, and revocation

- Store the client secret only in the deployment secret manager or protected Host environment, with least-privilege read access, rotation history, and audit logging. Never ship it to Cliente, the automatic local page, browser JavaScript, Onion configuration, Git, images, or backups without equivalent protection.
- Redact `client_secret`, authorization codes, access/refresh/ID tokens, cookies, PKCE verifiers, and full callback URLs from logs and diagnostics. Treat crash dumps and support bundles as sensitive.
- Keep sessions server-side where possible; expire idle and absolute sessions, rotate the session identifier after login, and revoke local sessions on logout/account disablement. Local logout does not revoke the user's Google account globally.
- If refresh tokens are ever requested for a separately approved Google API feature, encrypt them at rest, bind them to the LocalScale subject/environment, and request offline access only when necessary.
- To revoke a Google grant, use Google's [account third-party connections](https://myaccount.google.com/connections) page or the documented token-revocation endpoint `<https://oauth2.googleapis.com/revoke>` with the token. Then delete LocalScale's corresponding session/refresh-token record. On suspected secret compromise, disable/delete the affected client, rotate the secret, invalidate all dependent Host sessions, inspect audit logs, and create a replacement client rather than reusing exposed material.

## Phase 2 implementation notes

The control-plane adapter in `control-plane/src/lib.rs::google_oidc` uses `jsonwebtoken = 9.3.1` (RustCrypto/ring-backed RSA JWT verification) and `serde_json = 1.0.140` for strict wire parsing. Dependency versions are exact-pinned in `control-plane/Cargo.toml`; no Google credential file is read by the crate or its tests. `HttpTransport` is injected, receives a five-second request budget, and is the only network seam, so tests use deterministic in-memory responses.

Discovery is accepted only when the issuer is exactly `https://accounts.google.com`; authorization, token, and JWKS URLs must be HTTPS, have the expected Google host, and contain no query, fragment, or user-info. JWKS is bounded to 1 MiB/100 keys and cached for five minutes, with one forced refresh for rotation or signature/key failures. ID tokens require RS256, a matching RSA JWK `kid`/algorithm, and validated issuer, audience (string or array), expiration, issued-at skew, nonce, subject, and `email_verified`. Code exchange posts the configured redirect URI, client ID, opaque secret reference value, and PKCE verifier; request debug output redacts the body.

HTTP route/session integration remains intentionally unimplemented: the existing root loopback server is not treated as the authentication service, and no fake successful login was added.

- [Google OpenID Connect reference](https://developers.google.com/identity/openid-connect/reference)
- [Google OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect)
- [Google OAuth web-server flow](https://developers.google.com/identity/protocols/oauth2/web-server)
- [Google Cloud OAuth client setup](https://docs.cloud.google.com/iam/docs/auth-with-3lo-v2)
