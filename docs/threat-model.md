# LocalScale threat model

This document defines the security boundary for LocalScale's Google SSO deployment. It covers the automatically started local web page, Host and Cliente modes, the Onion transport, the control plane, and Google as the identity provider (IdP).

## Scope and assumptions

LocalScale has a **Host** that owns the control plane and starts a local browser page automatically. A **Cliente** connects to a Host and requests permitted operations. An **Onion** endpoint may provide reachability across an untrusted network. Google OIDC authenticates people; it does not decide LocalScale roles. The Host must make the final authorization decision for every operation.

Assumptions:

- The Host operating system and secret store are trusted within their stated administrative boundary; full Host compromise is an in-scope high-impact compromise, not something application controls can repair.
- The browser, Cliente, Onion relays, LAN, Internet, and other Hosts are potentially hostile or compromised.
- TLS/Onion transport provides confidentiality only when endpoint authentication and certificate/origin policy are also correct.
- Google availability, account recovery, and Workspace administration are external dependencies; LocalScale must fail closed when OIDC validation is unavailable or ambiguous.

## Assets and security goals

| Asset | Goal |
|---|---|
| Google client secret, token exchange, and OIDC transaction state | Confidentiality, single use, rapid rotation/revocation |
| LocalScale identity mapping and role/policy | Integrity; map by Google `sub`, not mutable email |
| Host control-plane API and Cliente pairing/session | Authentication, authorization, replay resistance, auditability |
| User data and Host configuration | Confidentiality and integrity; least privilege per operation |
| Local browser session and automatic startup flow | Confidentiality, CSRF resistance, predictable origin, safe logout |
| Availability and audit records | Resist abuse; preserve enough redacted evidence for incident response |

## Trust boundaries and data flow

1. **Local UI/browser boundary:** Host starts a local web page and opens it in the user's browser. The page talks to the Host at the exact configured local origin. Browser JavaScript is untrusted with respect to client secrets.
2. **Browser ↔ Google boundary:** Host begins Authorization Code + PKCE. Google returns a code to the exact registered callback. The browser must not receive a client secret or tokens intended for server storage.
3. **Host ↔ Google boundary:** Host exchanges the code and validates discovery metadata, signature, issuer, audience, time claims, nonce, and email verification. Google claims are authentication input, not LocalScale authorization.
4. **Cliente ↔ Host boundary:** Cliente requests are authenticated and authorized by the Host. Cliente-supplied user IDs, roles, paths, or mode flags are untrusted input.
5. **Onion/network boundary:** Onion relays and network peers can observe, delay, drop, replay, or attempt to alter traffic. The application must preserve endpoint authentication, origin policy, session protections, and authorization over this transport.
6. **Host ↔ control plane boundary:** The control plane is the policy enforcement point. Every command checks the authenticated session/peer, role, resource ownership, freshness, and operation authorization; UI visibility is not authorization.

## Threats and controls

| Threat | Surface | Required control / residual risk |
|---|---|---|
| Authorization-code interception or injection | Local UI, Onion, callback | Exact redirect URIs; Authorization Code + PKCE S256; single-use server transaction; TLS; reject missing/expired/reused state and code. A fully compromised Host can still steal the exchange. |
| CSRF/login CSRF | Local UI, staging, production | Cryptographically random state bound to the initiating browser transaction; SameSite cookies; validate state before token exchange; rotate session ID after login. |
| Token replay or substitution | Host, control plane | Validate signature/JWKS, `iss`, `aud`, `exp`, `iat`, nonce; never accept bearer tokens from Cliente as proof of Google identity; short-lived local sessions; revoke on incident. |
| Wrong-account or account-link takeover | IdP, Host identity store | Key records by issuer + `sub`; require `email_verified`; do not silently merge by email; explicit relink/recovery procedure. `hd` is only a policy hint, not proof. |
| Client-secret exposure | Local files, logs, page, Cliente, Onion, CI | Secret-manager/environment injection only; no browser/Cliente delivery; redaction; least privilege; separate clients per environment; rotation and incident playbook. |
| Malicious local web page or port confusion | Automatic startup/local UI | Bind to loopback; fixed/configured port; print/open the exact origin; reject unexpected Host header/origin; do not fall back to `0.0.0.0` or a broad callback; use a one-time local transaction. A malware-controlled user account/OS remains trusted only by assumption. |
| Browser session theft/fixation | Local UI, production | Secure + HttpOnly + SameSite cookie; no tokens in URL/localStorage; short idle/absolute expiry; session rotation at login; CSRF protection for state-changing requests; logout invalidates server session. |
| Cliente impersonation or privilege escalation | Cliente ↔ Host | Pairing must be explicit, short-lived, and revocable; bind peer credentials to a Host record; authorize every request server-side; rate-limit pairing and sensitive commands; audit actor, peer, operation, and result. |
| Replay of Cliente commands | Cliente, Onion, control plane | Per-session/peer freshness and request IDs; reject duplicate IDs; bind authorization to the current session and resource; protect integrity in transit. |
| Onion endpoint enumeration, MITM, or downgrade | Onion | Treat Onion as untrusted transport; authenticate Host/session at the application layer; enforce HTTPS/origin and secure-cookie policy where applicable; never let Onion change redirect URI or role; monitor unusual failures. Onion routing does not prove the peer's identity. |
| SSRF/open redirect via post-login return path | Host callback/control plane | Store allowed return targets server-side or allow only fixed relative paths; never redirect to a user-supplied absolute URL; validate all outbound URLs and webhook-like configuration. |
| IdP outage, metadata/key rotation, or malformed response | Host ↔ Google | Use OIDC discovery and cached JWKS with bounded refresh; fail closed on invalid metadata/token; distinguish transient retry from authentication success; do not accept unsigned or stale tokens. Google remains an external availability dependency. |
| Overbroad Google consent | IdP, Data Access | Request only `openid email` and optionally `profile`; no unrelated Google API scopes by default; review External-app verification requirements. |
| Audit/log leakage | All components | Redact codes, tokens, cookies, secrets, state, nonce, verifier, and full callback URLs; protect logs; retain security events with stable subject/actor IDs and no raw credentials. |
| Host/control-plane compromise | Host, control plane | Least-privilege service account/user; protected secret store; OS patching; admin separation; signed/reviewed releases; backups protected; incident response includes secret rotation, session invalidation, peer revocation, and log review. Residual impact is total data/control-plane exposure. |
| Denial of service/resource exhaustion | Onion, control plane, Cliente | Rate-limit login, callbacks, pairing, and expensive commands; bounded request/body/timeouts; queue limits; circuit breakers; preserve an operator recovery path. |

## Mode-specific rules

### Host mode

The Host is the only component permitted to hold a Google client secret, exchange authorization codes, validate ID tokens, map identities to LocalScale policy, and issue local sessions. The automatic local-page startup must be deterministic and fail closed if it cannot bind the configured loopback address or callback. Host UI controls are convenience only; the control plane repeats all authorization checks.

### Cliente mode

Cliente is not an OAuth confidential client. It receives no Google secret, refresh token, or raw ID token. It authenticates to the Host using the configured pairing/session mechanism, presents a stable peer identity, and treats all Host responses as untrusted input for local rendering. Revoking a Cliente must immediately prevent new requests and invalidate active peer sessions.

### Onion mode

Onion exposure increases reachability, not trust. Require an authenticated Host session and, where designed, an independently authenticated Cliente peer. Keep callback and canonical-origin policy explicit; never accept a callback merely because it arrived over Onion. Rate-limit and audit Onion-originated authentication, pairing, and control-plane traffic.

## Abuse cases and acceptance criteria

- An attacker submits a callback with a valid code but another transaction's state: no session is created.
- An attacker changes `aud`, `iss`, signature, nonce, expiry, or redirect URI: authentication fails closed.
- A Cliente claims to be an admin or another Google subject: the Host ignores the claim and denies unless Host policy grants that action.
- A user opens the automatic local page twice or changes its port: only the matching one-time transaction succeeds.
- A request arrives through Onion with a downgraded/inconsistent origin: it is rejected or normalized to the canonical approved flow; it cannot bypass authorization.
- Logout, peer revocation, account disablement, or secret compromise invalidates affected local sessions and credentials within the documented operational window.
- Logs and support bundles contain no raw client secrets, authorization codes, tokens, cookies, PKCE material, or nonces.

## Monitoring and incident response

Alert on repeated invalid state/nonce/signature/audience failures, callback floods, pairing failures, new admin grants, unusual Onion origins, and secret-manager access anomalies. Preserve timestamp, environment, Host/Cliente mode, redacted actor/subject identifier, peer ID, request ID, outcome, and reason—never raw tokens.

On suspected compromise: disable affected access, revoke LocalScale sessions and Cliente pairings, revoke Google grants where applicable, rotate or replace the environment client secret, inspect audit logs, check Host integrity, and document scope before restoring service. Re-test local, staging, production, and Onion paths after recovery.

## References

- [Google OpenID Connect reference](https://developers.google.com/identity/openid-connect/reference)
- [Google OpenID Connect guide](https://developers.google.com/identity/openid-connect/openid-connect)
- [Google OAuth web-server flow](https://developers.google.com/identity/protocols/oauth2/web-server)
- [Google Cloud OAuth client setup](https://docs.cloud.google.com/iam/docs/auth-with-3lo-v2)
- [Google account third-party connections](https://myaccount.google.com/connections)
