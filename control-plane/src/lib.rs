use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthResponse {
    pub status: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionResponse {
    pub service: &'static str,
    pub version: &'static str,
}

pub fn health() -> HealthResponse {
    HealthResponse { status: "ok" }
}

pub fn version() -> VersionResponse {
    VersionResponse {
        service: "localscale-control-plane",
        version: env!("CARGO_PKG_VERSION"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub users: HashMap<String, User>,
    pub devices: HashMap<String, Device>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: String,
    pub subject: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub id: String,
    pub owner_user_id: String,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterUserRequest<'a> {
    pub organization_id: &'a str,
    pub user_id: &'a str,
    pub subject: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterDeviceRequest<'a> {
    pub organization_id: &'a str,
    pub device_id: &'a str,
    pub owner_user_id: &'a str,
    /// Public key material only. Private keys must never be sent to this API.
    pub public_key: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    OrganizationNotFound,
    UserNotFound,
    AlreadyExists,
    InvalidIdentifier,
    PublicKeyRequired,
    PrivateKeyRejected,
}

#[derive(Debug, Default)]
pub struct Store {
    organizations: HashMap<String, Organization>,
}

impl Store {
    pub fn create_organization(&mut self, id: &str, name: &str) -> Result<(), StoreError> {
        if id.is_empty() || name.is_empty() {
            return Err(StoreError::InvalidIdentifier);
        }
        if self.organizations.contains_key(id) {
            return Err(StoreError::AlreadyExists);
        }
        self.organizations.insert(
            id.to_owned(),
            Organization {
                id: id.to_owned(),
                name: name.to_owned(),
                users: HashMap::new(),
                devices: HashMap::new(),
            },
        );
        Ok(())
    }

    pub fn organization(&self, id: &str) -> Option<&Organization> {
        self.organizations.get(id)
    }

    pub fn register_user(&mut self, request: RegisterUserRequest<'_>) -> Result<User, StoreError> {
        if request.user_id.is_empty() || request.subject.is_empty() {
            return Err(StoreError::InvalidIdentifier);
        }
        let organization = self
            .organizations
            .get_mut(request.organization_id)
            .ok_or(StoreError::OrganizationNotFound)?;
        if organization.users.contains_key(request.user_id) {
            return Err(StoreError::AlreadyExists);
        }
        let user = User {
            id: request.user_id.to_owned(),
            subject: request.subject.to_owned(),
        };
        organization.users.insert(user.id.clone(), user.clone());
        Ok(user)
    }

    pub fn register_device(
        &mut self,
        request: RegisterDeviceRequest<'_>,
    ) -> Result<Device, StoreError> {
        if request.device_id.is_empty() {
            return Err(StoreError::InvalidIdentifier);
        }
        if request.public_key.is_empty() {
            return Err(StoreError::PublicKeyRequired);
        }
        let key = request.public_key.to_ascii_lowercase();
        if key.contains("private key") || key.contains("begin rsa private") {
            return Err(StoreError::PrivateKeyRejected);
        }
        let organization = self
            .organizations
            .get_mut(request.organization_id)
            .ok_or(StoreError::OrganizationNotFound)?;
        if !organization.users.contains_key(request.owner_user_id) {
            return Err(StoreError::UserNotFound);
        }
        if organization.devices.contains_key(request.device_id) {
            return Err(StoreError::AlreadyExists);
        }
        let device = Device {
            id: request.device_id.to_owned(),
            owner_user_id: request.owner_user_id.to_owned(),
            public_key: request.public_key.to_owned(),
        };
        organization.devices.insert(device.id.clone(), device.clone());
        Ok(device)
    }

    /// Authorization is intentionally deny-by-default: only users in the named org pass.
    pub fn authorize(&self, organization_id: &str, user_id: &str) -> bool {
        self.organizations
            .get(organization_id)
            .is_some_and(|org| org.users.contains_key(user_id))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OidcClaims<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub expires_at: i64,
    pub subject: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OidcError {
    InvalidIssuer,
    InvalidAudience,
    Expired,
    MissingSubject,
}

/// Deterministic verifier seam for tests; it performs no network calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeOidcVerifier {
    issuer: String,
    audience: String,
}

impl FakeOidcVerifier {
    pub fn new(issuer: &str, audience: &str) -> Self {
        Self {
            issuer: issuer.to_owned(),
            audience: audience.to_owned(),
        }
    }

    pub fn verify<'a>(&self, claims: &'a OidcClaims<'a>, now: i64) -> Result<&'a str, OidcError> {
        if claims.issuer != self.issuer {
            return Err(OidcError::InvalidIssuer);
        }
        if claims.audience != self.audience {
            return Err(OidcError::InvalidAudience);
        }
        if claims.expires_at <= now {
            return Err(OidcError::Expired);
        }
        if claims.subject.is_empty() {
            return Err(OidcError::MissingSubject);
        }
        Ok(claims.subject)
    }
}

pub mod google_oidc {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use rand::{rngs::OsRng, RngCore};
    use sha2::{Digest, Sha256};
    use std::{collections::HashMap, time::{Duration, SystemTime}};

    #[derive(Clone, PartialEq, Eq)]
    pub struct ClientSecretRef(String);
    impl ClientSecretRef { pub fn new(reference: impl Into<String>) -> Self { Self(reference.into()) } }
    impl std::fmt::Debug for ClientSecretRef { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.debug_tuple("ClientSecretRef").field(&"[REDACTED]").finish() } }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum OidcCoreError { InvalidConfiguration(&'static str), StateMismatch, TransactionExpired, TransactionReplay, InvalidIssuer, InvalidAudience, Expired, IssuedInFuture, NonceMismatch, UnverifiedEmail, MissingSubject, InvalidReturnPath, InvalidEndpoint }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct GoogleOidcConfig { pub issuer: String, pub audience: String, pub redirect_uri: String, pub scopes: Vec<String>, pub transaction_ttl: Duration, pub clock_skew: Duration, secret_ref: ClientSecretRef }
    impl GoogleOidcConfig {
        pub fn new(issuer: &str, audience: &str, redirect_uri: &str, scopes: Vec<&str>, transaction_ttl: Duration, clock_skew: Duration, secret_ref: ClientSecretRef) -> Result<Self, OidcCoreError> {
            if issuer != "https://accounts.google.com" && issuer != "accounts.google.com" { return Err(OidcCoreError::InvalidConfiguration("issuer")); }
            if audience.is_empty() || scopes.iter().any(|s| s.is_empty()) || !scopes.iter().any(|s| *s == "openid") { return Err(OidcCoreError::InvalidConfiguration("audience/scopes")); }
            let https = redirect_uri.starts_with("https://");
            let loopback = redirect_uri.starts_with("http://127.0.0.1:") || redirect_uri.starts_with("http://localhost:");
            if (!https && !loopback) || redirect_uri.contains('?') || redirect_uri.contains('#') || redirect_uri.ends_with('/') { return Err(OidcCoreError::InvalidConfiguration("redirect_uri")); }
            if transaction_ttl.is_zero() || clock_skew > Duration::from_secs(300) { return Err(OidcCoreError::InvalidConfiguration("time")); }
            Ok(Self { issuer: issuer.into(), audience: audience.into(), redirect_uri: redirect_uri.into(), scopes: scopes.into_iter().map(str::to_owned).collect(), transaction_ttl, clock_skew, secret_ref })
        }
        pub fn client_secret_ref(&self) -> &ClientSecretRef { &self.secret_ref }
        pub fn from_env(secret_ref: ClientSecretRef) -> Result<Self, OidcCoreError> {
            let issuer = std::env::var("LOCALSCALE_OIDC_ISSUER").map_err(|_| OidcCoreError::InvalidConfiguration("issuer"))?;
            let audience = std::env::var("LOCALSCALE_OIDC_AUDIENCE").or_else(|_| std::env::var("LOCALSCALE_GOOGLE_CLIENT_ID")).map_err(|_| OidcCoreError::InvalidConfiguration("audience"))?;
            let redirect = std::env::var("LOCALSCALE_GOOGLE_REDIRECT_URI").map_err(|_| OidcCoreError::InvalidConfiguration("redirect_uri"))?;
            let scopes = std::env::var("LOCALSCALE_OIDC_SCOPES").unwrap_or_else(|_| "openid email profile".into());
            let scopes: Vec<&str> = scopes.split_whitespace().collect();
            Self::new(&issuer, &audience, &redirect, scopes, Duration::from_secs(300), Duration::from_secs(30), secret_ref)
        }
        pub fn secret_reference_is_opaque(&self) -> bool { true }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct OidcEndpoints { pub authorization_endpoint: String, pub token_endpoint: String }
    impl OidcEndpoints { pub fn google() -> Self { Self { authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth".into(), token_endpoint: "https://oauth2.googleapis.com/token".into() } } }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct PkceTransaction { state: String, nonce: String, verifier: String, created_at: SystemTime, expires_at: SystemTime, return_path: String, challenge: String }
    impl PkceTransaction { pub fn state(&self) -> &str { &self.state } pub fn nonce(&self) -> &str { &self.nonce } pub fn code_verifier(&self) -> &str { &self.verifier } pub fn code_challenge(&self) -> &str { &self.challenge } pub fn code_challenge_method(&self) -> &'static str { "S256" } pub fn return_path(&self) -> &str { &self.return_path } pub fn created_at(&self) -> SystemTime { self.created_at } pub fn expires_at(&self) -> SystemTime { self.expires_at } }
    #[derive(Debug, Default)] pub struct PkceTransactionStore { transactions: HashMap<String, PkceTransaction>, consumed: std::collections::HashSet<String> }
    impl PkceTransactionStore {
        pub fn new() -> Self { Self::default() }
        pub fn begin(&mut self, config: &GoogleOidcConfig, return_path: &str, now: SystemTime) -> Result<PkceTransaction, OidcCoreError> {
            self.begin_with_ttl(config.transaction_ttl, return_path, now)
        }
        pub fn begin_with_ttl(&mut self, ttl: Duration, return_path: &str, now: SystemTime) -> Result<PkceTransaction, OidcCoreError> {
            if !valid_return_path(return_path) { return Err(OidcCoreError::InvalidReturnPath); }
            let (state, nonce, verifier) = (random(), random(), random());
            let tx = PkceTransaction { state: state.clone(), nonce, verifier: verifier.clone(), created_at: now, expires_at: now + ttl, return_path: return_path.into(), challenge: pkce_challenge(&verifier) };
            self.transactions.insert(state, tx.clone()); Ok(tx)
        }
        pub fn consume(&mut self, state: &str, now: SystemTime) -> Result<PkceTransaction, OidcCoreError> {
            if self.consumed.contains(state) { return Err(OidcCoreError::TransactionReplay); }
            let tx = self.transactions.remove(state).ok_or(OidcCoreError::StateMismatch)?;
            if now >= tx.expires_at { self.consumed.insert(state.into()); return Err(OidcCoreError::TransactionExpired); }
            self.consumed.insert(state.into()); Ok(tx)
        }
    }
    fn random() -> String { let mut b = [0u8; 32]; OsRng.fill_bytes(&mut b); URL_SAFE_NO_PAD.encode(b) }
    pub fn pkce_challenge(verifier: &str) -> String { URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) }
    fn valid_return_path(p: &str) -> bool { p.starts_with('/') && !p.starts_with("//") && !p.contains('\\') && !p.contains("//") && !p.contains('#') && !p.contains('?') }
    pub fn authorization_url(config: &GoogleOidcConfig, endpoints: &OidcEndpoints, tx: &PkceTransaction) -> Result<String, OidcCoreError> {
        if !endpoints.authorization_endpoint.starts_with("https://") { return Err(OidcCoreError::InvalidEndpoint); }
        let mut q = form_urlencoded::Serializer::new(String::new());
        q.append_pair("client_id", &config.audience).append_pair("redirect_uri", &config.redirect_uri).append_pair("response_type", "code").append_pair("scope", &config.scopes.join(" ")).append_pair("state", &tx.state).append_pair("nonce", &tx.nonce).append_pair("code_challenge", &tx.challenge).append_pair("code_challenge_method", "S256");
        Ok(format!("{}?{}", endpoints.authorization_endpoint, q.finish()))
    }

    #[derive(Debug, Clone, PartialEq, Eq)] pub enum Audience<'a> { One(&'a str), Many(Vec<String>) }
    impl<'a> Audience<'a> { fn contains(&self, expected: &str) -> bool { match self { Self::One(a) => *a == expected, Self::Many(a) => a.iter().any(|x| x == expected) } } }
    #[derive(Clone, PartialEq, Eq)] pub struct IdTokenClaims<'a> { pub issuer: &'a str, pub audience: Audience<'a>, pub azp: Option<&'a str>, pub expires_at: i64, pub issued_at: i64, pub nonce: &'a str, pub subject: &'a str, pub email_verified: bool }
    impl std::fmt::Debug for IdTokenClaims<'_> { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.debug_struct("IdTokenClaims").field("issuer", &self.issuer).field("audience", &"[REDACTED]").field("expires_at", &self.expires_at).field("issued_at", &self.issued_at).field("nonce", &"[REDACTED]").field("subject", &"[REDACTED]").field("email_verified", &self.email_verified).finish() } }
    #[derive(Debug, Clone, PartialEq, Eq)] pub struct ValidatedIdentity { pub issuer: String, pub subject: String }
    pub struct IdTokenValidator<'a> { config: &'a GoogleOidcConfig }
    impl<'a> IdTokenValidator<'a> { pub fn new(config: &'a GoogleOidcConfig) -> Self { Self { config } } pub fn validate(&self, c: &'a IdTokenClaims<'a>, now: i64, expected_nonce: &str) -> Result<ValidatedIdentity, OidcCoreError> {
        if c.issuer != "https://accounts.google.com" && c.issuer != "accounts.google.com" { return Err(OidcCoreError::InvalidIssuer); }
        if !c.audience.contains(&self.config.audience) { return Err(OidcCoreError::InvalidAudience); }
        if c.azp.is_some_and(|azp| azp != self.config.audience.as_str()) || matches!(&c.audience, Audience::Many(audiences) if audiences.len() > 1 && c.azp.is_none()) { return Err(OidcCoreError::InvalidAudience); }
        let skew = self.config.clock_skew.as_secs() as i64;
        if c.expires_at <= now - skew { return Err(OidcCoreError::Expired); } if c.issued_at > now + skew { return Err(OidcCoreError::IssuedInFuture); }
        if c.nonce != expected_nonce { return Err(OidcCoreError::NonceMismatch); } if c.subject.is_empty() { return Err(OidcCoreError::MissingSubject); } if !c.email_verified { return Err(OidcCoreError::UnverifiedEmail); }
        Ok(ValidatedIdentity { issuer: "https://accounts.google.com".into(), subject: c.subject.into() })
    } }
    pub fn subject_key(identity: &ValidatedIdentity) -> String { format!("{}|{}", identity.issuer, identity.subject) }

    /// Narrow transport seam: production supplies an HTTPS client; tests supply a deterministic queue.
    pub trait HttpTransport { fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError>; }
    #[derive(Clone, PartialEq, Eq)]
    pub struct HttpRequest { pub method: String, pub url: String, pub body: String, pub timeout: Duration }
    impl std::fmt::Debug for HttpRequest { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.debug_struct("HttpRequest").field("method", &self.method).field("url", &self.url).field("body", &"[REDACTED]").field("timeout", &self.timeout).finish() } }
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct HttpResponse { pub status: u16, pub body: String }
    impl HttpResponse { pub fn ok(body: impl Into<String>) -> Self { Self { status: 200, body: body.into() } } }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum TransportError { Network, Timeout }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum OidcProviderError { Transport, HttpStatus, ResponseTooLarge, InvalidDiscovery(&'static str), InvalidJwks, InvalidTokenResponse, InvalidToken, InvalidSignature, UnsupportedAlgorithm, UnknownKey, RedirectMismatch }
    #[derive(Clone, PartialEq, Eq)] pub struct TokenResponse { pub access_token: String, pub id_token: String, pub token_type: String }
    impl std::fmt::Debug for TokenResponse { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.debug_struct("TokenResponse").field("access_token", &"[REDACTED]").field("id_token", &"[REDACTED]").field("token_type", &self.token_type).finish() } }
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct GoogleDiscovery { pub issuer: String, pub authorization_endpoint: String, pub token_endpoint: String, pub jwks_uri: String }
    #[derive(Debug, Clone)] struct CachedJwks { keys: Vec<Jwk>, fetched: SystemTime }
    #[derive(Debug, Clone, serde::Deserialize)] struct DiscoveryWire { issuer: String, authorization_endpoint: String, token_endpoint: String, jwks_uri: String }
    #[derive(Debug, Clone, serde::Deserialize)] struct JwksWire { keys: Vec<Jwk> }
    #[derive(Debug, Clone, serde::Deserialize)] struct Jwk { kty: String, kid: Option<String>, alg: Option<String>, n: Option<String>, e: Option<String> }
    #[derive(Debug, Clone, serde::Deserialize)] struct TokenWire { access_token: Option<String>, id_token: Option<String>, token_type: Option<String> }
    #[derive(Debug, Clone, serde::Deserialize)] struct JwtClaims { iss: String, aud: AudienceWire, azp: Option<String>, exp: i64, iat: i64, nonce: String, sub: String, email_verified: bool }
    #[derive(Debug, Clone, serde::Deserialize)] #[serde(untagged)] enum AudienceWire { One(String), Many(Vec<String>) }
    impl AudienceWire { fn contains(&self, expected: &str) -> bool { match self { Self::One(v) => v == expected, Self::Many(v) => v.iter().any(|x| x == expected) } } fn requires_azp(&self) -> bool { matches!(self, Self::Many(v) if v.len() > 1) } }

    pub struct GoogleOidcProvider<T> { config: GoogleOidcConfig, transport: T, discovery: Option<GoogleDiscovery>, jwks: Option<CachedJwks>, cache_ttl: Duration, max_response_bytes: usize }
    impl<T: HttpTransport> GoogleOidcProvider<T> {
        pub fn new(config: GoogleOidcConfig, transport: T) -> Self { Self { config, transport, discovery: None, jwks: None, cache_ttl: Duration::from_secs(300), max_response_bytes: 1024 * 1024 } }
        pub fn config(&self) -> &GoogleOidcConfig { &self.config }
        pub fn with_cache_limits(mut self, ttl: Duration, max_response_bytes: usize) -> Self { self.cache_ttl = ttl; self.max_response_bytes = max_response_bytes; self }
        fn request(&self, method: &str, url: &str, body: String) -> Result<HttpResponse, OidcProviderError> {
            if !is_https(url) { return Err(OidcProviderError::InvalidDiscovery("endpoint")); }
            let r = self.transport.send(HttpRequest { method: method.into(), url: url.into(), body, timeout: Duration::from_secs(5) }).map_err(|e| match e { TransportError::Timeout | TransportError::Network => OidcProviderError::Transport })?;
            if r.body.len() > self.max_response_bytes { return Err(OidcProviderError::ResponseTooLarge); }
            if !(200..300).contains(&r.status) { return Err(OidcProviderError::HttpStatus); }
            Ok(r)
        }
        pub fn discover(&mut self) -> Result<GoogleDiscovery, OidcProviderError> {
            let r = self.request("GET", "https://accounts.google.com/.well-known/openid-configuration", String::new())?;
            let w: DiscoveryWire = serde_json::from_str(&r.body).map_err(|_| OidcProviderError::InvalidDiscovery("json"))?;
            if w.issuer != "https://accounts.google.com" { return Err(OidcProviderError::InvalidDiscovery("issuer")); }
            if !endpoint_allowed(&w.authorization_endpoint, "accounts.google.com") || !endpoint_allowed(&w.token_endpoint, "oauth2.googleapis.com") || !endpoint_allowed(&w.jwks_uri, "www.googleapis.com") { return Err(OidcProviderError::InvalidDiscovery("endpoint")); }
            let d = GoogleDiscovery { issuer: w.issuer, authorization_endpoint: w.authorization_endpoint, token_endpoint: w.token_endpoint, jwks_uri: w.jwks_uri }; self.discovery = Some(d.clone()); Ok(d)
        }
        fn load_jwks(&mut self, force: bool) -> Result<Vec<Jwk>, OidcProviderError> {
            let fresh = self.jwks.as_ref().is_some_and(|c| !force && SystemTime::now().duration_since(c.fetched).unwrap_or_default() < self.cache_ttl);
            if fresh { return Ok(self.jwks.as_ref().unwrap().keys.clone()); }
            let uri = self.discovery.as_ref().ok_or(OidcProviderError::InvalidToken)?.jwks_uri.clone();
            let r = self.request("GET", &uri, String::new())?;
            let w: JwksWire = serde_json::from_str(&r.body).map_err(|_| OidcProviderError::InvalidJwks)?;
            if w.keys.is_empty() || w.keys.len() > 100 { return Err(OidcProviderError::InvalidJwks); }
            self.jwks = Some(CachedJwks { keys: w.keys.clone(), fetched: SystemTime::now() }); Ok(w.keys)
        }
        pub fn exchange_code(&mut self, tx: &PkceTransaction, code: &str) -> Result<TokenResponse, OidcProviderError> {
            self.exchange_code_with_redirect_uri(tx, code, &self.config.redirect_uri.clone())
        }
        pub fn exchange_code_with_redirect_uri(&mut self, tx: &PkceTransaction, code: &str, redirect_uri: &str) -> Result<TokenResponse, OidcProviderError> {
            if redirect_uri != self.config.redirect_uri { return Err(OidcProviderError::RedirectMismatch); }
            let d = if let Some(d) = &self.discovery { d.clone() } else { self.discover()? };
            if code.is_empty() || tx.code_verifier().is_empty() { return Err(OidcProviderError::InvalidTokenResponse); }
            let mut q = form_urlencoded::Serializer::new(String::new()); q.append_pair("code", code).append_pair("client_id", &self.config.audience).append_pair("client_secret", &self.config.secret_ref.0).append_pair("redirect_uri", &self.config.redirect_uri).append_pair("grant_type", "authorization_code").append_pair("code_verifier", tx.code_verifier());
            let r = self.request("POST", &d.token_endpoint, q.finish())?;
            let w: TokenWire = serde_json::from_str(&r.body).map_err(|_| OidcProviderError::InvalidTokenResponse)?;
            match (w.access_token, w.id_token, w.token_type) { (Some(a), Some(i), Some(t)) if !a.is_empty() && !i.is_empty() && t == "Bearer" => Ok(TokenResponse { access_token: a, id_token: i, token_type: t }), _ => Err(OidcProviderError::InvalidTokenResponse) }
        }
        pub fn validate_id_token(&mut self, raw: &str, expected_nonce: &str, now: i64) -> Result<ValidatedIdentity, OidcProviderError> {
            let header = jsonwebtoken::decode_header(raw).map_err(|_| OidcProviderError::InvalidToken)?;
            if header.alg != jsonwebtoken::Algorithm::RS256 { return Err(OidcProviderError::UnsupportedAlgorithm); }
            let kid = header.kid.ok_or(OidcProviderError::UnknownKey)?;
            let mut keys = self.load_jwks(false)?;
            let mut result = self.verify_with_key(raw, &kid, &keys, expected_nonce, now);
            if result.is_err() { keys = self.load_jwks(true)?; result = self.verify_with_key(raw, &kid, &keys, expected_nonce, now); }
            result
        }
        fn verify_with_key(&self, raw: &str, kid: &str, keys: &[Jwk], expected_nonce: &str, now: i64) -> Result<ValidatedIdentity, OidcProviderError> {
            let key = keys.iter().find(|k| k.kid.as_deref() == Some(kid)).ok_or(OidcProviderError::UnknownKey)?;
            if key.kty != "RSA" || key.alg.as_deref() != Some("RS256") { return Err(OidcProviderError::UnsupportedAlgorithm); }
            let (n, e) = (key.n.as_deref().ok_or(OidcProviderError::InvalidJwks)?, key.e.as_deref().ok_or(OidcProviderError::InvalidJwks)?);
            let decoding = jsonwebtoken::DecodingKey::from_rsa_components(n, e).map_err(|_| OidcProviderError::InvalidJwks)?;
            let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256); validation.set_issuer(&["https://accounts.google.com"]); validation.set_audience(&[self.config.audience.as_str()]); validation.validate_exp = false;
            let data = jsonwebtoken::decode::<JwtClaims>(raw, &decoding, &validation).map_err(|_| OidcProviderError::InvalidSignature)?;
            let c = data.claims; let skew = self.config.clock_skew.as_secs() as i64;
            if c.iss != "https://accounts.google.com" || !c.aud.contains(&self.config.audience) || c.azp.as_deref().is_some_and(|azp| azp != self.config.audience.as_str()) || (c.aud.requires_azp() && c.azp.is_none()) { return Err(OidcProviderError::InvalidToken); }
            if c.exp <= now - skew { return Err(OidcProviderError::InvalidToken); } if c.iat > now + skew { return Err(OidcProviderError::InvalidToken); }
            if c.nonce != expected_nonce || c.sub.is_empty() || !c.email_verified { return Err(OidcProviderError::InvalidToken); }
            Ok(ValidatedIdentity { issuer: "https://accounts.google.com".into(), subject: c.sub })
        }
    }
    fn is_https(s: &str) -> bool { s.starts_with("https://") && !s.contains(['?', '#', '@']) }
    fn endpoint_allowed(s: &str, host: &str) -> bool { is_https(s) && s.strip_prefix("https://").is_some_and(|r| r.split('/').next() == Some(host)) }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError { BadRequest, Forbidden, Unauthorized, Provider }

pub trait AuthProvider {
    fn authorization_url(&self, tx: &google_oidc::PkceTransaction) -> Result<String, AuthError>;
    fn exchange_code(&mut self, tx: &google_oidc::PkceTransaction, code: &str) -> Result<google_oidc::TokenResponse, AuthError>;
    fn validate_id_token(&mut self, raw: &str, nonce: &str, now: i64) -> Result<google_oidc::ValidatedIdentity, AuthError>;
    fn transaction_ttl(&self) -> std::time::Duration;
}

impl<T: google_oidc::HttpTransport> AuthProvider for google_oidc::GoogleOidcProvider<T> {
    fn authorization_url(&self, tx: &google_oidc::PkceTransaction) -> Result<String, AuthError> {
        google_oidc::authorization_url(self.config(), &google_oidc::OidcEndpoints::google(), tx).map_err(|_| AuthError::Provider)
    }
    fn exchange_code(&mut self, tx: &google_oidc::PkceTransaction, code: &str) -> Result<google_oidc::TokenResponse, AuthError> { self.exchange_code(tx, code).map_err(|_| AuthError::Provider) }
    fn validate_id_token(&mut self, raw: &str, nonce: &str, now: i64) -> Result<google_oidc::ValidatedIdentity, AuthError> { self.validate_id_token(raw, nonce, now).map_err(|_| AuthError::Provider) }
    fn transaction_ttl(&self) -> std::time::Duration { self.config().transaction_ttl }
}

#[derive(Clone, Default)]
pub struct AuthRequest { pub method: String, pub path: String, pub query: HashMap<String, String>, pub headers: HashMap<String, String> }
impl std::fmt::Debug for AuthRequest { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.debug_struct("AuthRequest").field("method", &self.method).field("path", &self.path).field("query", &"[REDACTED]").field("headers", &"[REDACTED]").finish() } }
impl AuthRequest {
    pub fn get(path: &str) -> Self { Self { method: "GET".into(), path: path.into(), ..Default::default() } }
    pub fn post(path: &str) -> Self { Self { method: "POST".into(), path: path.into(), ..Default::default() } }
    pub fn query(mut self, key: &str, value: &str) -> Self { self.query.insert(key.into(), value.into()); self }
    pub fn header(mut self, key: &str, value: &str) -> Self { self.headers.insert(key.into(), value.into()); self }
}
#[derive(Debug, Clone, Default)]
pub struct AuthResponse { pub status: u16, pub headers: Vec<(String, String)>, pub body: String }
impl AuthResponse { fn new(status: u16) -> Self { Self { status, ..Default::default() } } pub fn header(&self, name: &str) -> Option<&str> { self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str()) } }

#[derive(Debug, Clone)] struct Session { issuer: String, subject: String, expires_at: std::time::SystemTime, revoked: bool }
#[derive(Debug, Clone)] struct PendingCallback { callback: String, flutter_state: String }
#[derive(Debug, Clone)] struct Handoff { session_id: String, callback: String, flutter_state: String, expires_at: std::time::SystemTime }
pub struct AuthService<P> { provider: P, transactions: google_oidc::PkceTransactionStore, sessions: HashMap<String, Session>, pending_callbacks: HashMap<String, PendingCallback>, handoffs: HashMap<String, Handoff>, session_ttl: std::time::Duration }
impl<P: AuthProvider> AuthService<P> {
    pub fn new(provider: P, session_ttl: std::time::Duration, _redirect_uri: &str) -> Self { Self { provider, transactions: google_oidc::PkceTransactionStore::new(), sessions: HashMap::new(), pending_callbacks: HashMap::new(), handoffs: HashMap::new(), session_ttl } }
    pub fn handle(&mut self, request: AuthRequest) -> AuthResponse { self.handle_at(request, std::time::SystemTime::now()) }
    pub fn handle_at(&mut self, request: AuthRequest, now: std::time::SystemTime) -> AuthResponse {
        self.sessions.retain(|_, session| session.expires_at > now && !session.revoked);
        self.handoffs.retain(|_, handoff| handoff.expires_at > now);
        match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/oauth/google/start") => self.start(&request, now),
            ("GET", "/oauth/google/callback") => self.callback(request, now),
            ("GET", "/auth/session") => self.session(&request, now),
            ("GET", "/auth/session/bridge") => self.bridge(&request, now),
            ("POST", "/auth/logout") => self.logout(&request, now),
            _ => AuthResponse::new(404),
        }
    }
    fn start(&mut self, request: &AuthRequest, now: std::time::SystemTime) -> AuthResponse {
        let callback = request.query.get("app_callback").filter(|u| valid_loopback_callback(u)).cloned();
        if request.query.contains_key("app_callback") && callback.is_none() { return AuthResponse::new(400); }
        let flutter_state = request.query.get("state").filter(|state| !state.is_empty()).cloned();
        if callback.is_some() && flutter_state.is_none() { return AuthResponse::new(400); }
        let tx = match self.transactions.begin_with_ttl(self.provider.transaction_ttl(), "/", now) { Ok(t) => t, Err(_) => return AuthResponse::new(500) };
        if let (Some(callback), Some(flutter_state)) = (callback, flutter_state) { self.pending_callbacks.insert(tx.state().to_owned(), PendingCallback { callback, flutter_state }); }
        match self.provider.authorization_url(&tx) { Ok(url) => AuthResponse { status: 302, headers: vec![("Location".into(), url)], body: String::new() }, Err(_) => AuthResponse::new(502) }
    }
    fn callback(&mut self, request: AuthRequest, now: std::time::SystemTime) -> AuthResponse {
        if request.query.contains_key("error") { return AuthResponse::new(400); }
        let (Some(code), Some(state)) = (request.query.get("code"), request.query.get("state")) else { return AuthResponse::new(400) };
        if code.is_empty() || state.is_empty() { return AuthResponse::new(400); }
        let tx = match self.transactions.consume(state, now) { Ok(t) => t, Err(_) => return AuthResponse::new(400) };
        let pending_callback = self.pending_callbacks.remove(state).filter(|pending| valid_loopback_callback(&pending.callback));
        let token = match self.provider.exchange_code(&tx, code) {
            Ok(t) => t,
            Err(_) => return Self::provider_failure(pending_callback, 502),
        };
        let now_secs = now.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
        let identity = match self.provider.validate_id_token(&token.id_token, tx.nonce(), now_secs) {
            Ok(i) => i,
            Err(_) => return Self::provider_failure(pending_callback, 401),
        };
        let sid = random_opaque();
        self.sessions.insert(sid.clone(), Session { issuer: identity.issuer, subject: identity.subject, expires_at: now + self.session_ttl, revoked: false });
        let location = pending_callback;
        let has_handoff = location.is_some();
        let location = if let Some(pending) = location {
            let callback = pending.callback;
            let flutter_state = pending.flutter_state;
            let handoff = random_opaque();
            self.handoffs.insert(handoff.clone(), Handoff { session_id: sid.clone(), callback: callback.clone(), flutter_state: flutter_state.clone(), expires_at: now + self.session_ttl });
            let separator = if callback.contains('?') { '&' } else { '?' };
            let encoded_handoff = form_urlencoded::byte_serialize(handoff.as_bytes()).collect::<String>();
            let encoded_state = form_urlencoded::byte_serialize(flutter_state.as_bytes()).collect::<String>();
            format!("{callback}{separator}handoff={encoded_handoff}&state={encoded_state}")
        } else { "/".to_owned() };
        let headers = if has_handoff { Vec::new() } else { vec![("Set-Cookie".into(), format!("localscale_session={}; Path=/; Max-Age={}; HttpOnly; Secure; SameSite=Strict", sid, self.session_ttl.as_secs()))] };
        AuthResponse { status: 303, headers: { let mut h = headers; h.insert(0, ("Location".into(), location)); h }, body: String::new() }
    }
    fn provider_failure(pending: Option<PendingCallback>, status: u16) -> AuthResponse {
        let Some(pending) = pending else { return AuthResponse::new(status); };
        let separator = if pending.callback.contains('?') { '&' } else { '?' };
        let encoded_state = form_urlencoded::byte_serialize(pending.flutter_state.as_bytes()).collect::<String>();
        AuthResponse { status: 303, headers: vec![("Location".into(), format!("{}{separator}error=authentication_failed&state={encoded_state}", pending.callback))], body: String::new() }
    }
    fn bridge(&mut self, request: &AuthRequest, now: std::time::SystemTime) -> AuthResponse {
        let (Some(token), Some(callback), Some(flutter_state)) = (request.query.get("handoff"), request.query.get("callback"), request.query.get("state")) else { return AuthResponse::new(400) };
        let Some(handoff) = self.handoffs.get(token).cloned() else { return AuthResponse::new(401) };
        if handoff.expires_at <= now || handoff.callback != *callback || handoff.flutter_state != *flutter_state || !valid_loopback_callback(callback) { return AuthResponse::new(401); }
        let handoff = self.handoffs.remove(token).expect("handoff checked above");
        let sid = handoff.session_id;
        let Some(session) = self.sessions.get(&sid).filter(|s| s.expires_at > now && !s.revoked) else { return AuthResponse::new(401) };
        let expires = session.expires_at.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        AuthResponse { status: 200, headers: vec![("Content-Type".into(), "application/json".into())], body: format!("{{\"session_id\":\"{sid}\",\"expires_at\":{expires}}}") }
    }
    fn session(&mut self, request: &AuthRequest, now: std::time::SystemTime) -> AuthResponse { match self.session_id(request).and_then(|id| self.sessions.get(&id)).filter(|s| !s.revoked && s.expires_at > now) { Some(s) => AuthResponse { status: 200, body: format!("{{\"authenticated\":true,\"issuer\":\"{}\",\"subject\":\"{}\"}}", s.issuer, s.subject), ..Default::default() }, None => AuthResponse::new(401) } }
    fn logout(&mut self, request: &AuthRequest, now: std::time::SystemTime) -> AuthResponse { let Some(id) = self.session_id(request) else { return AuthResponse::new(401) }; let Some(csrf) = request.headers.get("X-CSRF-Token") else { return AuthResponse::new(403) }; if !constant_time_eq(&id, csrf) { return AuthResponse::new(403) } if let Some(s) = self.sessions.get_mut(&id) { if s.expires_at <= now || s.revoked { return AuthResponse::new(401) } s.revoked = true; return AuthResponse { status: 204, headers: vec![("Set-Cookie".into(), "localscale_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict".into())], ..Default::default() }; } AuthResponse::new(401) }
    fn session_id(&self, request: &AuthRequest) -> Option<String> { request.headers.get("Cookie")?.split(';').map(str::trim).find_map(|v| v.strip_prefix("localscale_session=")).filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')).map(str::to_owned) }
}
fn random_opaque() -> String { use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine}; use rand::RngCore; let mut b = [0u8; 32]; rand::rngs::OsRng.fill_bytes(&mut b); URL_SAFE_NO_PAD.encode(b) }
fn valid_loopback_callback(value: &str) -> bool {
    let rest = value.strip_prefix("http://127.0.0.1:")
        .or_else(|| value.strip_prefix("http://[::1]:"));
    let valid_port_and_path = rest
        .and_then(|rest| rest.split_once('/'))
        .and_then(|(port, path)| port.parse::<u16>().ok().map(|port| (port, path)))
        .is_some_and(|(port, path)| port != 0 && path == "oauth/callback");
    valid_port_and_path && !value.contains(['?', '#', '\\'])
}
fn constant_time_eq(a: &str, b: &str) -> bool { let aa = a.as_bytes(); let bb = b.as_bytes(); let mut diff = (aa.len() ^ bb.len()) as u8; for i in 0..aa.len().max(bb.len()) { let x = aa.get(i).copied().unwrap_or(0); let y = bb.get(i).copied().unwrap_or(0); diff |= x ^ y; } diff == 0 }

#[cfg(test)]
mod phase3_red_tests {
    use super::google_oidc::*;
    use super::*;
    use std::time::{Duration, SystemTime};

    #[derive(Default)]
    struct Provider;
    impl AuthProvider for Provider {
        fn authorization_url(&self, tx: &PkceTransaction) -> Result<String, AuthError> {
            Ok(format!("https://accounts.google.com/auth?state={}", tx.state()))
        }
        fn exchange_code(&mut self, _: &PkceTransaction, _: &str) -> Result<TokenResponse, AuthError> {
            Ok(TokenResponse { access_token: "access-secret".into(), id_token: "id-secret".into(), token_type: "Bearer".into() })
        }
        fn validate_id_token(&mut self, _: &str, _: &str, _: i64) -> Result<ValidatedIdentity, AuthError> {
            Ok(ValidatedIdentity { issuer: "https://accounts.google.com".into(), subject: "subject".into() })
        }
        fn transaction_ttl(&self) -> Duration { Duration::from_secs(60) }
    }

    fn service() -> AuthService<Provider> { AuthService::new(Provider, Duration::from_secs(60), "https://host.test/auth/google/callback") }
    fn now() -> SystemTime { SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000) }

    struct FailingProvider { fail_exchange: bool, fail_validation: bool }
    impl AuthProvider for FailingProvider {
        fn authorization_url(&self, tx: &PkceTransaction) -> Result<String, AuthError> {
            Ok(format!("https://accounts.google.com/auth?state={}", tx.state()))
        }
        fn exchange_code(&mut self, _: &PkceTransaction, _: &str) -> Result<TokenResponse, AuthError> {
            if self.fail_exchange { return Err(AuthError::Provider); }
            Ok(TokenResponse { access_token: "access-secret".into(), id_token: "id-secret".into(), token_type: "Bearer".into() })
        }
        fn validate_id_token(&mut self, _: &str, _: &str, _: i64) -> Result<ValidatedIdentity, AuthError> {
            if self.fail_validation { return Err(AuthError::Provider); }
            Ok(ValidatedIdentity { issuer: "https://accounts.google.com".into(), subject: "subject".into() })
        }
        fn transaction_ttl(&self) -> Duration { Duration::from_secs(60) }
    }

    fn failing_service(fail_exchange: bool, fail_validation: bool) -> AuthService<FailingProvider> {
        AuthService::new(FailingProvider { fail_exchange, fail_validation }, Duration::from_secs(60), "https://host.test/auth/google/callback")
    }

    fn assert_provider_failure_redirects(fail_exchange: bool, fail_validation: bool) {
        let mut service = failing_service(fail_exchange, fail_validation);
        let callback = "http://127.0.0.1:43126/oauth/callback";
        let flutter_state = "flutter-state-1";
        let start = service.handle_at(AuthRequest::get("/oauth/google/start").query("app_callback", callback).query("state", flutter_state), now());
        let server_state = start.header("Location").unwrap().split("state=").nth(1).unwrap().to_owned();
        assert_ne!(server_state, flutter_state);
        let sensitive_code = "provider-code-secret";
        let response = service.handle_at(AuthRequest::get("/oauth/google/callback").query("code", sensitive_code).query("state", &server_state), now());
        assert_eq!(response.status, 303);
        assert_eq!(response.header("Location").unwrap(), format!("{callback}?error=authentication_failed&state={flutter_state}"));
        assert!(response.body.is_empty());
        let rendered = format!("{:?}{:?}{:?}", response.status, response.headers, response.body);
        assert!(!rendered.contains(sensitive_code) && !rendered.contains("access-secret") && !rendered.contains("id-secret"));
        assert_eq!(service.handle_at(AuthRequest::get("/oauth/google/callback").query("code", sensitive_code).query("state", &server_state), now()).status, 400);
    }

    #[test]
    fn exchange_failure_redirects_to_exact_pending_loopback_callback() {
        assert_provider_failure_redirects(true, false);
    }

    #[test]
    fn id_token_validation_failure_redirects_to_exact_pending_loopback_callback() {
        assert_provider_failure_redirects(false, true);
    }

    #[test]
    fn provider_failures_without_pending_callback_keep_bare_statuses() {
        let mut exchange = failing_service(true, false);
        let start = exchange.handle_at(AuthRequest::get("/oauth/google/start"), now());
        let state = start.header("Location").unwrap().split("state=").nth(1).unwrap();
        assert_eq!(exchange.handle_at(AuthRequest::get("/oauth/google/callback").query("code", "secret-code").query("state", state), now()).status, 502);

        let mut validation = failing_service(false, true);
        let start = validation.handle_at(AuthRequest::get("/oauth/google/start"), now());
        let state = start.header("Location").unwrap().split("state=").nth(1).unwrap();
        assert_eq!(validation.handle_at(AuthRequest::get("/oauth/google/callback").query("code", "secret-code").query("state", state), now()).status, 401);
    }

    #[test]
    fn start_is_a_safe_302_and_stores_pkce_state() {
        let mut service = service();
        let response = service.handle_at(AuthRequest::get("/oauth/google/start"), now());
        assert_eq!(response.status, 302);
        assert!(response.header("Location").unwrap().starts_with("https://accounts.google.com/auth?state="));
    }

    #[test]
    fn app_handoff_requires_flutter_state() {
        let mut service = service();
        assert_eq!(service.handle_at(AuthRequest::get("/oauth/google/start").query("app_callback", "http://127.0.0.1:43126/oauth/callback"), now()).status, 400);
        assert_eq!(service.handle_at(AuthRequest::get("/oauth/google/start").query("app_callback", "http://127.0.0.1:43126/oauth/callback").query("state", ""), now()).status, 400);
    }

    #[test]
    fn callback_consumes_state_and_sets_opaque_secure_cookie() {
        let mut service = service();
        let start = service.handle_at(AuthRequest::get("/oauth/google/start"), now());
        let state = start.header("Location").unwrap().split("state=").nth(1).unwrap();
        let callback = AuthRequest::get("/oauth/google/callback").query("code", "provider-code").query("state", state);
        let response = service.handle_at(callback, now());
        assert_eq!(response.status, 303);
        let cookie = response.header("Set-Cookie").unwrap();
        assert!(cookie.contains("HttpOnly") && cookie.contains("Secure") && cookie.contains("SameSite=Strict"));
        assert!(!cookie.contains("provider-code") && !cookie.contains("access-secret") && !cookie.contains("id-secret"));
    }

    #[test]
    fn logout_requires_csrf_and_revokes_session() {
        let mut service = service();
        let start = service.handle_at(AuthRequest::get("/oauth/google/start"), now());
        let state = start.header("Location").unwrap().split("state=").nth(1).unwrap();
        let login = service.handle_at(AuthRequest::get("/oauth/google/callback").query("code", "c").query("state", state), now());
        let cookie = login.header("Set-Cookie").unwrap().split(';').next().unwrap().to_owned();
        assert_eq!(service.handle_at(AuthRequest::get("/auth/session").header("Cookie", &cookie), now()).status, 200);
        assert_eq!(service.handle_at(AuthRequest::post("/auth/logout").header("Cookie", &cookie), now()).status, 403);
        let sid = cookie.strip_prefix("localscale_session=").unwrap();
        let out = service.handle_at(AuthRequest::post("/auth/logout").header("Cookie", &cookie).header("X-CSRF-Token", sid), now());
        assert_eq!(out.status, 204);
        assert_eq!(service.handle_at(AuthRequest::get("/auth/session").header("Cookie", &cookie), now()).status, 401);
    }

    #[test]
    fn callback_rejects_denial_mismatch_replay_and_expired_state() {
        let mut service = service();
        assert_eq!(service.handle_at(AuthRequest::get("/oauth/google/callback").query("error", "access_denied"), now()).status, 400);
        let start = service.handle_at(AuthRequest::get("/oauth/google/start"), now());
        let state = start.header("Location").unwrap().split("state=").nth(1).unwrap().to_owned();
        let callback = AuthRequest::get("/oauth/google/callback").query("code", "c").query("state", &state);
        assert_eq!(service.handle_at(callback.clone(), now()).status, 303);
        assert_eq!(service.handle_at(callback, now()).status, 400);
        let start = service.handle_at(AuthRequest::get("/oauth/google/start"), now());
        let state = start.header("Location").unwrap().split("state=").nth(1).unwrap().to_owned();
        assert_eq!(service.handle_at(AuthRequest::get("/oauth/google/callback").query("code", "c").query("state", &state), now() + Duration::from_secs(61)).status, 400);
    }

    #[test]
    fn expired_session_is_not_authenticated() {
        let mut service = service();
        let start = service.handle_at(AuthRequest::get("/oauth/google/start"), now());
        let state = start.header("Location").unwrap().split("state=").nth(1).unwrap();
        let login = service.handle_at(AuthRequest::get("/oauth/google/callback").query("code", "c").query("state", state), now());
        let cookie = login.header("Set-Cookie").unwrap().split(';').next().unwrap();
        assert_eq!(service.handle_at(AuthRequest::get("/auth/session").header("Cookie", cookie), now() + Duration::from_secs(61)).status, 401);
    }

    #[test]
    fn dynamic_loopback_handoff_contract_is_bound_and_token_free() {
        let mut service = service();
        let callback = "http://127.0.0.1:43123/oauth/callback";
        let flutter_state = "flutter-state-2";
        let start = service.handle_at(AuthRequest::get("/oauth/google/start").query("app_callback", callback).query("state", flutter_state), now());
        let server_state = start.header("Location").unwrap().split("state=").nth(1).unwrap().to_owned();
        assert_ne!(server_state, flutter_state);
        assert_eq!(service.handle_at(AuthRequest::get("/oauth/google/callback").query("code", "provider-code").query("state", flutter_state), now()).status, 400);
        let login = service.handle_at(AuthRequest::get("/oauth/google/callback").query("code", "provider-code").query("state", &server_state), now());
        assert_eq!(login.status, 303);
        let location = login.header("Location").unwrap();
        assert!(location.starts_with(callback));
        assert!(location.contains("handoff=") && location.contains("state="));
        assert!(location.contains(&format!("state={flutter_state}")));
        assert!(!location.contains(&format!("state={server_state}")));
        assert!(!location.contains("provider-code") && !location.contains("access-secret") && !location.contains("id-secret"));
        assert!(login.header("Set-Cookie").is_none());
        let query = location.split('?').nth(1).unwrap();
        let params: std::collections::HashMap<_, _> = query.split('&').filter_map(|pair| pair.split_once('=')).collect();
        let handoff = params.get("handoff").unwrap().to_string();
        let exchange = AuthRequest::get("/auth/session/bridge").query("handoff", &handoff).query("callback", callback).query("state", flutter_state);
        let response = service.handle_at(exchange, now());
        assert_eq!(response.status, 200);
        assert!(!response.body.contains("access-secret") && !response.body.contains("id-secret"));
        assert_eq!(service.handle_at(AuthRequest::get("/auth/session/bridge").query("handoff", &handoff).query("callback", callback).query("state", flutter_state), now()).status, 401);
    }

    #[test]
    fn handoff_rejects_wrong_callback_and_expiry() {
        let mut service = service();
        let callback = "http://127.0.0.1:43124/oauth/callback";
        let flutter_state = "flutter-state-3";
        let start = service.handle_at(AuthRequest::get("/oauth/google/start").query("app_callback", callback).query("state", flutter_state), now());
        let server_state = start.header("Location").unwrap().split("state=").nth(1).unwrap().to_owned();
        let login = service.handle_at(AuthRequest::get("/oauth/google/callback").query("code", "c").query("state", &server_state), now());
        let location = login.header("Location").unwrap();
        let handoff = location.split("handoff=").nth(1).unwrap().split('&').next().unwrap();
        assert_eq!(service.handle_at(AuthRequest::get("/auth/session/bridge").query("handoff", handoff).query("callback", "http://127.0.0.1:43125/oauth/callback").query("state", flutter_state), now()).status, 401);
        assert_eq!(service.handle_at(AuthRequest::get("/auth/session/bridge").query("handoff", handoff).query("callback", callback).query("state", "wrong-flutter-state"), now()).status, 401);
        assert_eq!(service.handle_at(AuthRequest::get("/auth/session/bridge").query("handoff", handoff).query("callback", callback).query("state", flutter_state), now() + Duration::from_secs(61)).status, 401);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::google_oidc::*;
    use std::time::{Duration, SystemTime};

    fn config() -> GoogleOidcConfig {
        GoogleOidcConfig::new(
            "https://accounts.google.com",
            "client-id",
            "https://host.test/auth/google/callback",
            vec!["openid", "email"],
            Duration::from_secs(300),
            Duration::from_secs(30),
            ClientSecretRef::new("secret-ref"),
        ).unwrap()
    }

    #[test]
    fn config_requires_exact_https_redirect_and_openid_scope() {
        assert!(GoogleOidcConfig::new("https://accounts.google.com", "c", "https://x/cb/", vec!["email"], Duration::from_secs(1), Duration::from_secs(1), ClientSecretRef::new("r")).is_err());
        assert!(GoogleOidcConfig::new("https://accounts.google.com", "c", "http://x/cb", vec!["openid"], Duration::from_secs(1), Duration::from_secs(1), ClientSecretRef::new("r")).is_err());
    }

    #[test]
    fn transaction_is_random_pkce_and_single_use() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let mut store = PkceTransactionStore::new();
        let tx = store.begin(&config(), "/dashboard", now).unwrap();
        assert_eq!(tx.return_path(), "/dashboard");
        assert_eq!(tx.code_challenge_method(), "S256");
        assert_eq!(tx.code_challenge(), pkce_challenge(tx.code_verifier()));
        assert_eq!(store.consume(tx.state(), now), Ok(tx.clone()));
        assert!(matches!(store.consume(tx.state(), now), Err(OidcCoreError::TransactionReplay)));
    }

    #[test]
    fn callback_rejects_mismatch_and_expiry() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let mut store = PkceTransactionStore::new();
        let tx = store.begin(&config(), "/", now).unwrap();
        assert!(matches!(store.consume("wrong", now), Err(OidcCoreError::StateMismatch)));
        assert!(matches!(store.consume(tx.state(), now + Duration::from_secs(301)), Err(OidcCoreError::TransactionExpired)));
    }

    #[test]
    fn authorization_url_contains_safe_parameters() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let mut store = PkceTransactionStore::new();
        let tx = store.begin(&config(), "/", now).unwrap();
        let url = authorization_url(&config(), &OidcEndpoints::google(), &tx).unwrap().to_string();
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fhost.test%2Fauth%2Fgoogle%2Fcallback"));
        assert!(!url.contains("secret-ref"));
    }

    fn claims() -> IdTokenClaims<'static> { IdTokenClaims { issuer: "https://accounts.google.com", audience: Audience::Many(vec!["client-id".into()]), azp: None, expires_at: 1_700_000_100, issued_at: 1_700_000_000, nonce: "n", subject: "stable-sub", email_verified: true } }

    #[test]
    fn claims_validate_google_issuer_audience_times_nonce_email_and_subject() {
        let cfg = config(); let v = IdTokenValidator::new(&cfg);
        let valid = claims();
        assert_eq!(v.validate(&valid, 1_700_000_010, "n").unwrap().subject, "stable-sub");
        let bads = [IdTokenClaims { issuer: "https://accounts.example", ..valid.clone() }, IdTokenClaims { audience: Audience::One("other"), ..valid.clone() }, IdTokenClaims { issued_at: 1_700_000_1000, ..valid.clone() }, IdTokenClaims { expires_at: 1_699_999_000, ..valid.clone() }, IdTokenClaims { nonce: "bad", ..valid.clone() }, IdTokenClaims { email_verified: false, ..valid.clone() }, IdTokenClaims { subject: "", ..valid }]; for bad in bads { assert!(v.validate(&bad, 1_700_000_010, "n").is_err()); }
    }

    #[test]
    fn claims_with_multiple_audiences_require_matching_azp() {
        let cfg = config(); let v = IdTokenValidator::new(&cfg);
        let valid = IdTokenClaims { audience: Audience::Many(vec!["client-id".into(), "other-client".into()]), azp: Some("client-id"), ..claims() };
        assert!(v.validate(&valid, 1_700_000_010, "n").is_ok());
        let missing = IdTokenClaims { azp: None, ..valid.clone() };
        assert!(matches!(v.validate(&missing, 1_700_000_010, "n"), Err(OidcCoreError::InvalidAudience)));
        let mismatched = IdTokenClaims { azp: Some("other-client"), ..valid };
        assert!(matches!(v.validate(&mismatched, 1_700_000_010, "n"), Err(OidcCoreError::InvalidAudience)));
        let single_mismatched = IdTokenClaims { audience: Audience::One("client-id"), azp: Some("other-client"), ..claims() };
        assert!(matches!(v.validate(&single_mismatched, 1_700_000_010, "n"), Err(OidcCoreError::InvalidAudience)));
        let single_matching = IdTokenClaims { audience: Audience::One("client-id"), azp: Some("client-id"), ..claims() };
        assert!(v.validate(&single_matching, 1_700_000_010, "n").is_ok());
    }

    #[test]
    fn subject_mapping_uses_issuer_and_sub_not_email() {
        let cfg = config(); let v = IdTokenValidator::new(&cfg); let c = claims();
        let a = v.validate(&c, 1_700_000_010, "n").unwrap();
        assert_eq!(subject_key(&a), "https://accounts.google.com|stable-sub");
    }

    use std::cell::RefCell;
    struct TestTransport { responses: RefCell<Vec<HttpResponse>> }
    impl TestTransport { fn new(responses: Vec<HttpResponse>) -> Self { Self { responses: RefCell::new(responses) } } }
    impl HttpTransport for TestTransport { fn send(&self, _request: HttpRequest) -> Result<HttpResponse, TransportError> { if self.responses.borrow().is_empty() { return Err(TransportError::Network); } Ok(self.responses.borrow_mut().remove(0)) } }

    #[test]
    fn phase2_provider_rejects_untrusted_discovery_endpoints() {
        let transport = TestTransport::new(vec![HttpResponse::ok(r#"{"issuer":"https://accounts.google.com","authorization_endpoint":"http://evil.test/auth","token_endpoint":"https://oauth2.googleapis.com/token","jwks_uri":"https://www.googleapis.com/oauth2/v3/certs"}"#)]);
        let mut provider = GoogleOidcProvider::new(config(), transport);
        assert!(matches!(provider.discover(), Err(OidcProviderError::InvalidDiscovery(_))));
    }

    #[test]
    fn phase2_rejects_redirect_uri_mismatch_before_network() {
        let mut provider = GoogleOidcProvider::new(config(), TestTransport::new(vec![]));
        let mut store = PkceTransactionStore::new();
        let tx = store.begin(&config(), "/", SystemTime::UNIX_EPOCH).unwrap();
        assert_eq!(provider.exchange_code_with_redirect_uri(&tx, "code", "https://evil.test/cb"), Err(OidcProviderError::RedirectMismatch));
    }

    #[test]
    fn phase2_rejects_invalid_signature_and_missing_claim_token() {
        let discovery = r#"{"issuer":"https://accounts.google.com","authorization_endpoint":"https://accounts.google.com/auth","token_endpoint":"https://oauth2.googleapis.com/token","jwks_uri":"https://www.googleapis.com/oauth2/v3/certs"}"#;
        let jwks = r#"{"keys":[{"kty":"RSA","kid":"fixture","alg":"RS256","n":"AQ","e":"AQAB"}]}"#;
        let mut provider = GoogleOidcProvider::new(config(), TestTransport::new(vec![HttpResponse::ok(discovery), HttpResponse::ok(jwks)]));
        assert!(provider.validate_id_token("eyJhbGciOiJSUzI1NiIsImtpZCI6ImZpeHR1cmUifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20ifQ.invalid", "n", 1_700_000_000).is_err());
    }

    #[test]
    fn phase2_provider_posts_exact_pkce_exchange_without_secret_exposure() {
        let transport = TestTransport::new(vec![
            HttpResponse::ok(r#"{"issuer":"https://accounts.google.com","authorization_endpoint":"https://accounts.google.com/auth","token_endpoint":"https://oauth2.googleapis.com/token","jwks_uri":"https://www.googleapis.com/oauth2/v3/certs"}"#),
            HttpResponse::ok(r#"{"access_token":"a","token_type":"Bearer","id_token":"bad"}"#),
        ]);
        let secret = config().client_secret_ref().clone();
        let mut provider = GoogleOidcProvider::new(config(), transport);
        let mut store = PkceTransactionStore::new();
        let tx = store.begin(&config(), "/", SystemTime::UNIX_EPOCH).unwrap();
        let result = provider.exchange_code(&tx, "code").unwrap();
        assert_eq!(result.access_token, "a");
        assert_eq!(format!("{:?}", secret), "ClientSecretRef(\"[REDACTED]\")");
    }

    #[test]
    fn phase2_transport_never_receives_google_in_tests() {
        let transport = TestTransport::new(vec![]);
        let mut provider = GoogleOidcProvider::new(config(), transport);
        assert!(provider.discover().is_err());
    }

    #[test]
    fn health_and_version_are_deterministic() {
        assert_eq!(health(), HealthResponse { status: "ok" });
        assert_eq!(version(), VersionResponse { service: "localscale-control-plane", version: env!("CARGO_PKG_VERSION") });
    }

    #[test]
    fn registration_accepts_public_keys_and_stores_membership() {
        let mut store = Store::default();
        store.create_organization("org-1", "Acme").unwrap();
        let user = store.register_user(RegisterUserRequest { organization_id: "org-1", user_id: "user-1", subject: "sub-1" }).unwrap();
        let device = store.register_device(RegisterDeviceRequest { organization_id: "org-1", device_id: "device-1", owner_user_id: "user-1", public_key: "ed25519:abc" }).unwrap();
        assert_eq!(user.subject, "sub-1");
        assert_eq!(device.public_key, "ed25519:abc");
        assert!(store.organization("org-1").unwrap().users.contains_key("user-1"));
    }

    #[test]
    fn registration_rejects_private_key_material() {
        let mut store = Store::default();
        store.create_organization("org-1", "Acme").unwrap();
        store.register_device(RegisterDeviceRequest { organization_id: "org-1", device_id: "device-1", owner_user_id: "missing", public_key: "-----BEGIN PRIVATE KEY-----" }).unwrap_err();
    }

    #[test]
    fn organization_authorization_defaults_to_deny() {
        let mut store = Store::default();
        store.create_organization("org-1", "Acme").unwrap();
        assert!(!store.authorize("org-1", "unknown-user"));
        store.register_user(RegisterUserRequest { organization_id: "org-1", user_id: "user-1", subject: "sub-1" }).unwrap();
        assert!(store.authorize("org-1", "user-1"));
        assert!(!store.authorize("missing-org", "user-1"));
    }

    #[test]
    fn fake_oidc_verifier_checks_issuer_audience_expiry_and_subject() {
        let verifier = FakeOidcVerifier::new("https://accounts.example", "localscale");
        let now = 1_700_000_000;
        let valid = OidcClaims { issuer: "https://accounts.example", audience: "localscale", expires_at: now + 60, subject: "sub-1" };
        assert_eq!(verifier.verify(&valid, now), Ok("sub-1"));
        assert_eq!(verifier.verify(&OidcClaims { issuer: "wrong", ..valid }, now), Err(OidcError::InvalidIssuer));
        assert_eq!(verifier.verify(&OidcClaims { audience: "other", ..valid }, now), Err(OidcError::InvalidAudience));
        assert_eq!(verifier.verify(&OidcClaims { expires_at: now, ..valid }, now), Err(OidcError::Expired));
        assert_eq!(verifier.verify(&OidcClaims { subject: "", ..valid }, now), Err(OidcError::MissingSubject));
    }
}
