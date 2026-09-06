use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::path::{Path, PathBuf};
use localscale_control_plane::{AuthRequest, AuthResponse};
use localscale_agent_protocol::{ClientConfig, HostInvitation};

pub mod tor_runtime;

pub trait AuthHandler: Send {
    fn handle(&mut self, request: AuthRequest) -> AuthResponse;
}

impl<P: localscale_control_plane::AuthProvider + Send> AuthHandler
    for localscale_control_plane::AuthService<P>
{
    fn handle(&mut self, request: AuthRequest) -> AuthResponse {
        localscale_control_plane::AuthService::handle(self, request)
    }
}

type SharedAuth = Arc<Mutex<Box<dyn AuthHandler>>>;

const VERSION: &str = "0.1.0";
const MAX_REQUEST_BYTES: usize = 16 * 1024;
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const MAX_CONNECTIONS: usize = 16;

fn lock_recover<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn remaining_budget(started: std::time::Instant, total: std::time::Duration, now: std::time::Instant) -> Option<std::time::Duration> {
    let elapsed = now.saturating_duration_since(started);
    (elapsed < total).then(|| total - elapsed)
}

pub fn health_response() -> &'static str {
    r#"{"status":"ok","service":"localscale"}"#
}

pub fn configuration_html() -> &'static str {
    r#"<!doctype html>
<html lang="en"><meta charset="utf-8"><title>LocalScale</title>
<body><h1>LocalScale</h1><p>Local service is running.</p></body></html>"#
}

#[derive(Clone)]
struct AgentState {
    mode: Arc<Mutex<String>>,
    service_state: Arc<Mutex<String>>,
    peer: Arc<Mutex<PeerState>>,
    auth: Option<SharedAuth>,
    peer_store: Option<Arc<Mutex<PeerStore>>>,
}

#[derive(Clone, Default)]
struct PeerState {
    configured: bool,
    node_id: Option<String>,
    host_node_id: Option<String>,
    endpoint: Option<String>,
    transport: &'static str,
    approved: bool,
    revoked: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerRecord {
    pub role: String,
    pub node_id: String,
    pub host_node_id: Option<String>,
    pub endpoint: String,
    pub invitation_secret: String,
    pub approved: bool,
    pub revoked: bool,
}

#[derive(Clone, Debug)]
pub struct PeerStore { path: PathBuf, record: Option<PeerRecord> }

impl PeerStore {
    pub fn open(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        let record = if path.exists() { Some(Self::read_record(&path)?) } else { None };
        Ok(Self { path, record })
    }
    pub fn record(&self) -> Option<&PeerRecord> { self.record.as_ref() }
    pub fn ephemeral() -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(format!("localscale-peer-{}-{}.json", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos()));
        Self::open(path)
    }
    pub fn configure(&mut self, record: PeerRecord) -> std::io::Result<()> {
        self.write_record(&record)?; self.record = Some(record); Ok(())
    }
    pub fn set_approval(&mut self, approved: bool) -> std::io::Result<()> {
        let Some(mut record) = self.record.clone() else { return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "peer is not configured")); };
        record.approved = approved; record.revoked = !approved;
        self.write_record(&record)?; self.record = Some(record); Ok(())
    }
    fn read_record(path: &Path) -> std::io::Result<PeerRecord> {
        let body = std::fs::read_to_string(path)?;
        let fields = parse_json_fields(&body).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid peer store"))?;
        let role = fields.get("role").cloned().unwrap_or_default();
        let node_id = fields.get("node_id").cloned().unwrap_or_default();
        let endpoint = fields.get("endpoint").cloned().unwrap_or_default();
        let invitation_secret = fields.get("invitation_secret").cloned().unwrap_or_default();
        let approved = fields.get("approved").map(|v| v == "true").unwrap_or(false);
        let revoked = fields.get("revoked").map(|v| v == "true").unwrap_or(true);
        let host_node_id = fields.get("host_node_id").cloned().filter(|v| !v.is_empty());
        if role.is_empty() || node_id.is_empty() || endpoint.is_empty() || invitation_secret.is_empty() { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "incomplete peer store")); }
        Ok(PeerRecord { role, node_id, host_node_id, endpoint, invitation_secret, approved, revoked })
    }
    fn write_record(&self, record: &PeerRecord) -> std::io::Result<()> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)?;
        let tmp = self.path.with_extension("tmp");
        let body = format!("{{\"role\":\"{}\",\"node_id\":\"{}\",\"host_node_id\":\"{}\",\"endpoint\":\"{}\",\"invitation_secret\":\"{}\",\"approved\":{},\"revoked\":{}}}", record.role, record.node_id, record.host_node_id.as_deref().unwrap_or(""), record.endpoint, record.invitation_secret, record.approved, record.revoked);
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(body.as_bytes())?; file.sync_all()?;
        #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?; }
        std::fs::rename(&tmp, &self.path)?;
        if let Ok(dir) = std::fs::File::open(parent) { let _ = dir.sync_all(); }
        Ok(())
    }
}

impl Default for AgentState {
    fn default() -> Self {
        Self {
            mode: Arc::new(Mutex::new("cliente".to_string())),
            service_state: Arc::new(Mutex::new("stopped".to_string())),
            peer: Arc::new(Mutex::new(PeerState { transport: "unavailable", ..PeerState::default() })),
            auth: None,
            peer_store: PeerStore::ephemeral().ok().map(|s| Arc::new(Mutex::new(s))),
        }
    }
}

pub fn serve(listener: TcpListener) -> std::io::Result<()> {
    serve_with_auth_handler(listener, None)
}

pub fn serve_with_auth(listener: TcpListener, auth: Box<dyn AuthHandler>) -> std::io::Result<()> {
    serve_with_auth_handler(listener, Some(Arc::new(Mutex::new(auth))))
}

fn serve_with_auth_handler(listener: TcpListener, auth: Option<SharedAuth>) -> std::io::Result<()> {
    let peer_store = std::env::var_os("LOCALSCALE_PEER_STORE").map(PeerStore::open).transpose()?;
    let state = AgentState { auth, peer_store: peer_store.map(|s| Arc::new(Mutex::new(s))), ..AgentState::default() };
    if let Some(store) = &state.peer_store {
        if let Some(record) = lock_recover(store).record().cloned() {
            let mut peer = lock_recover(&state.peer);
            peer.configured = true; peer.node_id = Some(record.node_id); peer.host_node_id = record.host_node_id; peer.endpoint = Some(record.endpoint);
            peer.approved = record.approved; peer.revoked = record.revoked;
        }
    }
    let active = Arc::new(Mutex::new(0usize));
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("LocalScale connection failed: {error}");
                continue;
            }
        };
        let accepted_at = std::time::Instant::now();
        let mut count = lock_recover(&active);
        if *count >= MAX_CONNECTIONS {
            drop(count);
            let mut stream = stream;
            let _ = stream.write_all(http_response("503 Service Unavailable", "text/plain; charset=utf-8", "connection limit reached").as_bytes());
            continue;
        }
        *count += 1;
        drop(count);
        let state = state.clone();
        let active = active.clone();
        std::thread::spawn(move || {
            let _guard = ConnectionGuard { active };
            if let Err(error) = handle_connection(stream, &state, accepted_at) {
                eprintln!("LocalScale request failed: {error}");
            }
        });
    }
    Ok(())
}

struct ConnectionGuard { active: Arc<Mutex<usize>> }
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let mut active = lock_recover(&self.active);
        *active = active.saturating_sub(1);
    }
}

fn handle_connection(mut stream: TcpStream, state: &AgentState, accepted_at: std::time::Instant) -> std::io::Result<()> {
    let mut request = Vec::with_capacity(4096);
    let mut buffer = [0_u8; 1024];
    while request.len() < MAX_REQUEST_BYTES {
        let elapsed = accepted_at.elapsed();
        if elapsed >= REQUEST_TIMEOUT { return Ok(()); }
        stream.set_read_timeout(Some(REQUEST_TIMEOUT - elapsed))?;
        let read = match stream.read(&mut buffer) {
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => return Ok(()),
            Err(error) => return Err(error),
        };
        if read == 0 { break; }
        request.extend_from_slice(&buffer[..read]);
        if let Some(header_end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
            let header = String::from_utf8_lossy(&request[..header_end]);
            let content_length = header.lines().find_map(|line| {
                line.strip_prefix("Content-Length:").and_then(|value| value.trim().parse::<usize>().ok())
            }).unwrap_or(0);
            if content_length > MAX_REQUEST_BYTES || header_end + 4 + content_length > MAX_REQUEST_BYTES {
                return stream.write_all(http_response("413 Payload Too Large", "text/plain; charset=utf-8", "request too large").as_bytes());
            }
            if request.len() >= header_end + 4 + content_length { break; }
        }
    }
    let request = String::from_utf8_lossy(&request);
    let response = response_for_request_with_state(&request, state);
    let Some(write_budget) = remaining_budget(accepted_at, REQUEST_TIMEOUT, std::time::Instant::now()) else { return Ok(()); };
    stream.set_write_timeout(Some(write_budget))?;
    stream.write_all(response.as_bytes())
}

pub fn response_for_request(request: &str) -> String {
    response_for_request_with_state(request, &AgentState::default())
}

pub fn response_for_request_with_auth<A: AuthHandler>(request: &str, auth: &mut A) -> String {
    let head = request.split("\r\n\r\n").next().unwrap_or("");
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let (path, query_string) = target.split_once('?').unwrap_or((target, ""));
    let headers: Vec<(&str, &str)> = lines.filter_map(|line| line.split_once(':').map(|(name, value)| (name, value.trim()))).collect();
    let host = headers.iter().find_map(|(name, value)| name.eq_ignore_ascii_case("host").then_some(*value)).unwrap_or("");
    if !is_loopback_host(host) { return http_response("403 Forbidden", "text/plain; charset=utf-8", "local requests only"); }
    let query = match parse_query(query_string) { Ok(query) => query, Err(()) => return http_response("400 Bad Request", "text/plain; charset=utf-8", "malformed query") };
    let request_headers = headers.into_iter().map(|(name, value)| {
        let name = if name.eq_ignore_ascii_case("cookie") { "Cookie" } else if name.eq_ignore_ascii_case("x-csrf-token") { "X-CSRF-Token" } else { name };
        (name.to_owned(), value.to_owned())
    }).collect();
    auth_http_response(auth.handle(AuthRequest { method: method.to_owned(), path: path.to_owned(), query, headers: request_headers }))
}

fn response_for_request_with_state(request: &str, state: &AgentState) -> String {
    let mut sections = request.splitn(2, "\r\n\r\n");
    let head = sections.next().unwrap_or("");
    let body = sections.next().unwrap_or("");
    let mut fields = head.split("\r\n");
    let request_line = fields.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let (path, query_string) = target.split_once('?').unwrap_or((target, ""));
    let headers: Vec<(&str, &str)> = fields.filter_map(|line| line.split_once(':').map(|(name, value)| (name, value.trim()))).collect();
    let host = headers.iter().find_map(|(name, value)| name.eq_ignore_ascii_case("host").then_some(*value)).unwrap_or("");

    if !is_loopback_host(host) {
        return http_response("403 Forbidden", "text/plain; charset=utf-8", "local requests only");
    }
    if matches!(path, "/oauth/google/start" | "/oauth/google/callback" | "/auth/session" | "/auth/session/bridge" | "/auth/logout") {
        let Some(auth) = &state.auth else {
            return http_response("503 Service Unavailable", "text/plain; charset=utf-8", "authentication unavailable");
        };
        let query = match parse_query(query_string) {
            Ok(query) => query,
            Err(()) => return http_response("400 Bad Request", "text/plain; charset=utf-8", "malformed query"),
        };
        let request_headers = headers.into_iter().map(|(name, value)| {
            let name = if name.eq_ignore_ascii_case("cookie") { "Cookie" } else if name.eq_ignore_ascii_case("x-csrf-token") { "X-CSRF-Token" } else { name };
            (name.to_owned(), value.to_owned())
        }).collect();
        let response = lock_recover(auth).handle(AuthRequest { method: method.to_owned(), path: path.to_owned(), query, headers: request_headers });
        return auth_http_response(response);
    }
    match (method, path) {
        ("GET", "/api/v1/status") => service_status(state),
        ("GET", "/api/v1/peer/status") => peer_status(state),
        ("POST", "/api/v1/peer/config") => set_peer_config(body, state),
        ("POST", "/api/v1/peer/approve") => set_peer_approval(true, state),
        ("POST", "/api/v1/peer/revoke") => set_peer_approval(false, state),
        ("POST", "/api/v1/mode") => set_mode(body, state, true),
        ("POST", "/api/v1/service/start") => set_service_state("running", state),
        ("POST", "/api/v1/service/stop") => set_service_state("stopped", state),
        ("POST", "/api/v1/sync") => service_status(state),
        ("GET", "/") | ("GET", "/config") => http_response("200 OK", "text/html; charset=utf-8", configuration_html()),
        ("GET", "/health") => http_response("200 OK", "application/json", health_response()),
        ("GET", "/version") => http_response("200 OK", "application/json", &format!(r#"{{"version":"{VERSION}","service":"localscale"}}"#)),
        ("GET", "/status") => service_status(state),
        ("GET", "/mode") => {
            let mode = lock_recover(&state.mode).clone();
            http_response("200 OK", "application/json", &format!(r#"{{"mode":"{mode}"}}"#))
        }
        ("POST", "/mode") => set_mode(body, state, false),
        ("GET", "/onion") => http_response("200 OK", "application/json", r#"{"enabled":false,"address":null}"#),
        ("GET", "/diagnostics") | ("GET", "/api/v1/diagnostics") => diagnostics_status(state),
        _ => http_response("404 Not Found", "text/plain; charset=utf-8", "not found"),
    }
}

fn parse_query(query: &str) -> Result<std::collections::HashMap<String, String>, ()> {
    let mut result = std::collections::HashMap::new();
    if query.is_empty() { return Ok(result); }
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        result.insert(strict_decode(key)?, strict_decode(value)?);
    }
    Ok(result)
}

fn strict_decode(input: &str) -> Result<String, ()> {
    let mut bytes = Vec::with_capacity(input.len());
    let raw = input.as_bytes();
    let mut i = 0;
    while i < raw.len() {
        match raw[i] {
            b'+' => bytes.push(b' '),
            b'%' if i + 2 < raw.len() => {
                let hi = (raw[i + 1] as char).to_digit(16).ok_or(())?;
                let lo = (raw[i + 2] as char).to_digit(16).ok_or(())?;
                bytes.push((hi * 16 + lo) as u8); i += 2;
            }
            b'%' => return Err(()),
            byte => bytes.push(byte),
        }
        i += 1;
    }
    String::from_utf8(bytes).map_err(|_| ())
}

fn auth_http_response(response: AuthResponse) -> String {
    let status = match response.status {
        200 => "200 OK", 204 => "204 No Content", 302 => "302 Found", 303 => "303 See Other",
        400 => "400 Bad Request", 401 => "401 Unauthorized", 403 => "403 Forbidden", 502 => "502 Bad Gateway",
        _ => "500 Internal Server Error",
    };
    let mut output = format!("HTTP/1.1 {status}\r\n");
    for (name, value) in response.headers { output.push_str(&format!("{name}: {value}\r\n")); }
    output.push_str(&format!("Content-Length: {}\r\nConnection: close\r\n\r\n{}", response.body.len(), response.body));
    output
}

fn service_status(state: &AgentState) -> String {
    let mode = lock_recover(&state.mode).clone();
    let service_state = lock_recover(&state.service_state).clone();
    let peer = lock_recover(&state.peer);
    http_response("200 OK", "application/json", &format!(
        r#"{{"mode":"{mode}","state":"{service_state}","onion_endpoint":null,"peer_configured":{},"peer_transport":"{}"}}"#,
        peer.configured, peer.transport))
}

fn peer_status(state: &AgentState) -> String {
    let peer = lock_recover(&state.peer);
    let json = format!(r#"{{"configured":{},"node_id":{},"host_node_id":{},"onion_endpoint":{},"transport":"{}","connected":false,"approved":{},"revoked":{}}}"#,
        peer.configured, optional_json(&peer.node_id), optional_json(&peer.host_node_id), optional_json(&peer.endpoint), peer.transport, peer.approved, peer.revoked);
    http_response("200 OK", "application/json", &json)
}

fn diagnostics_status(state: &AgentState) -> String {
    let peer = lock_recover(&state.peer);
    let json = format!(r#"{{"service":"localscale","loopback":true,"external_network":false,"peer_configured":{},"peer_transport":"{}","peer_connected":false}}"#, peer.configured, peer.transport);
    http_response("200 OK", "application/json", &json)
}

fn optional_json(value: &Option<String>) -> String {
    value.as_ref().map(|value| format!("\"{}\"", value)).unwrap_or_else(|| "null".into())
}

fn set_peer_config(body: &str, state: &AgentState) -> String {
    let fields = match parse_json_fields(body) { Some(fields) => fields, None => return http_response("400 Bad Request", "application/json", r#"{"error":"invalid_peer_config"}"#) };
    let role = fields.get("role").map(String::as_str).unwrap_or("");
    let result: Result<(String, Option<String>, String), ()> = match role {
        "host" => HostInvitation::new(
            fields.get("node_id").map(String::as_str).unwrap_or(""),
            fields.get("onion_endpoint").map(String::as_str).unwrap_or(""),
            fields.get("invitation_secret").map(String::as_str).unwrap_or(""),
        ).map(|invitation| (invitation.host_node_id().to_string(), None, invitation.public_endpoint().to_string())).map_err(|_| ()),
        "cliente" => {
            let invitation = HostInvitation::new(
                fields.get("host_node_id").map(String::as_str).unwrap_or(""),
                fields.get("onion_endpoint").map(String::as_str).unwrap_or(""),
                fields.get("invitation_secret").map(String::as_str).unwrap_or(""),
            ).map_err(|_| ());
            match invitation {
                Ok(invitation) => ClientConfig::from_invitation(&invitation, fields.get("node_id").map(String::as_str).unwrap_or(""))
                    .map(|config| (fields.get("node_id").cloned().unwrap_or_default(), Some(config.host_node_id().to_string()), config.public_endpoint().to_string())).map_err(|_| ()),
                Err(error) => Err(error),
            }
        }
        _ => Err(()),
    };
    let Ok((node_id, host_node_id, endpoint)) = result else { return http_response("400 Bad Request", "application/json", r#"{"error":"invalid_peer_config"}"#) };
    let Some(store) = &state.peer_store else { return http_response("503 Service Unavailable", "application/json", r#"{"error":"peer_store_unavailable"}"#) };
    let record = PeerRecord { role: role.to_string(), node_id: node_id.clone(), host_node_id: host_node_id.clone(), endpoint: endpoint.clone(), invitation_secret: fields.get("invitation_secret").cloned().unwrap_or_default(), approved: false, revoked: false };
    if lock_recover(store).configure(record).is_err() { return http_response("500 Internal Server Error", "application/json", r#"{"error":"peer_store_write_failed"}"#); }
    let mut peer = lock_recover(&state.peer);
    peer.configured = true; peer.node_id = Some(node_id); peer.host_node_id = host_node_id; peer.endpoint = Some(endpoint); peer.transport = "unavailable"; peer.approved = false; peer.revoked = false;
    drop(peer);
    peer_status(state)
}

fn set_peer_approval(approved: bool, state: &AgentState) -> String {
    let Some(store) = &state.peer_store else { return http_response("503 Service Unavailable", "application/json", r#"{"error":"peer_store_unavailable"}"#) };
    if lock_recover(store).set_approval(approved).is_err() { return http_response("404 Not Found", "application/json", r#"{"error":"peer_not_configured"}"#); }
    let mut peer = lock_recover(&state.peer); peer.approved = approved; peer.revoked = !approved; drop(peer); peer_status(state)
}

fn parse_json_fields(body: &str) -> Option<std::collections::HashMap<String, String>> {
    let mut output = std::collections::HashMap::new();
    let body = body.trim().strip_prefix('{')?.strip_suffix('}')?.trim();
    if body.is_empty() { return Some(output); }
    for item in body.split(',') {
        let (key, value) = item.split_once(':')?;
        let key = key.trim().strip_prefix('"')?.strip_suffix('"')?;
        let value = value.trim();
        let value = if let Some(value) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) { value } else if matches!(value, "true" | "false") { value } else { return None };
        if key.is_empty() || value.bytes().any(|byte| byte < 0x20 || byte == b'\\') { return None; }
        output.insert(key.to_string(), value.to_string());
    }
    Some(output)
}

fn set_service_state(service_state: &str, state: &AgentState) -> String {
    *lock_recover(&state.service_state) = service_state.to_string();
    service_status(state)
}

fn set_mode(body: &str, state: &AgentState, contract: bool) -> String {
    let mode = parse_mode(body, contract);
    let Some(mode) = mode else {
        return http_response("400 Bad Request", "text/plain; charset=utf-8", "mode must be host or cliente")
    };
    *lock_recover(&state.mode) = mode.to_string();
    if contract { service_status(state) } else {
        http_response("200 OK", "application/json", &format!(r#"{{"mode":"{mode}"}}"#))
    }
}

fn parse_mode(body: &str, contract: bool) -> Option<&'static str> {
    let body = body.trim().strip_prefix('{')?.strip_suffix('}')?.trim();
    let body = body.strip_prefix('"')?;
    let key_end = body.find('"')?;
    if &body[..key_end] != "mode" { return None; }
    let rest = body[key_end + 1..].trim_start().strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let value_end = rest.find('"')?;
    let value = &rest[..value_end];
    // Valid modes contain no quotes, backslashes, or controls, so JSON interpolation stays escaped-safe.
    if value.bytes().any(|byte| byte == b'\\' || byte < 0x20) { return None; }
    if !rest[value_end + 1..].trim().is_empty() { return None; }
    match value {
        "host" => Some("host"),
        "cliente" => Some("cliente"),
        "client" if !contract => Some("client"),
        _ => None,
    }
}

fn is_loopback_host(host: &str) -> bool {
    let host = host.trim();
    let host = if let Some(stripped) = host.strip_prefix('[') {
        stripped.split(']').next().unwrap_or("")
    } else if host.matches(':').count() == 1 {
        host.split(':').next().unwrap_or("")
    } else {
        host
    };
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1"
}

fn http_response(status: &str, content_type: &str, body: &str) -> String {
    format!("HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
}

#[cfg(test)]
mod tests {
    use super::{configuration_html, health_response};
    use localscale_control_plane::{google_oidc::{PkceTransaction, TokenResponse, ValidatedIdentity}, AuthError, AuthProvider, AuthService};
    use std::time::Duration;

    #[derive(Default)]
    struct DeterministicProvider;
    impl AuthProvider for DeterministicProvider {
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

    fn auth_service() -> AuthService<DeterministicProvider> {
        AuthService::new(DeterministicProvider, Duration::from_secs(60), "http://127.0.0.1:8765/oauth/google/callback")
    }

    #[test]
    fn auth_start_redirects_through_root_http_adapter() {
        let mut auth = auth_service();
        let response = super::response_for_request_with_auth(
            "GET /oauth/google/start HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", &mut auth);
        assert!(response.starts_with("HTTP/1.1 302 Found"), "{response}");
        assert!(response.contains("Location: https://accounts.google.com/auth?state="));
    }

    #[test]
    fn auth_callback_session_logout_use_actual_http_translation() {
        let mut auth = auth_service();
        let start = super::response_for_request_with_auth(
            "GET /oauth/google/start HTTP/1.1\r\nHost: localhost\r\n\r\n", &mut auth);
        let location = start.lines().find(|line| line.starts_with("Location: ")).unwrap();
        let state = location.split("state=").nth(1).unwrap();
        let callback = super::response_for_request_with_auth(
            &format!("GET /oauth/google/callback?code=provider-code&state={state} HTTP/1.1\r\nHost: localhost\r\n\r\n"), &mut auth);
        assert!(callback.starts_with("HTTP/1.1 303 See Other"), "{callback}");
        let cookie = callback.lines().find(|line| line.starts_with("Set-Cookie: ")).unwrap().strip_prefix("Set-Cookie: ").unwrap().split(';').next().unwrap();
        assert!(callback.contains("Location: /\r\n"));
        assert!(callback.contains("HttpOnly") && callback.contains("Secure") && callback.contains("SameSite=Strict"));
        let replay = super::response_for_request_with_auth(&format!("GET /oauth/google/callback?code=provider-code&state={state} HTTP/1.1\r\nHost: localhost\r\n\r\n"), &mut auth);
        assert!(replay.starts_with("HTTP/1.1 400 Bad Request"));
        let session = super::response_for_request_with_auth(&format!("GET /auth/session HTTP/1.1\r\nHost: localhost\r\nCookie: {cookie}\r\n\r\n"), &mut auth);
        assert!(session.starts_with("HTTP/1.1 200 OK"));
        let missing_csrf = super::response_for_request_with_auth(&format!("POST /auth/logout HTTP/1.1\r\nHost: localhost\r\nCookie: {cookie}\r\n\r\n"), &mut auth);
        assert!(missing_csrf.starts_with("HTTP/1.1 403 Forbidden"));
        let sid = cookie.strip_prefix("localscale_session=").unwrap();
        let logout = super::response_for_request_with_auth(&format!("POST /auth/logout HTTP/1.1\r\nHost: localhost\r\nCookie: {cookie}\r\nX-CSRF-Token: {sid}\r\n\r\n"), &mut auth);
        assert!(logout.starts_with("HTTP/1.1 204 No Content"));
        assert!(!callback.contains("provider-code") && !callback.contains("access-secret") && !callback.contains("id-secret"));
    }

    #[test]
    fn handoff_exchange_is_reachable_through_root_http_adapter() {
        let mut auth = auth_service();
        let app_callback = "http://127.0.0.1:43123/oauth/callback";
        let flutter_state = "flutter-state-root";
        let start = super::response_for_request_with_auth(&format!("GET /oauth/google/start?app_callback={app_callback}&state={flutter_state} HTTP/1.1\r\nHost: localhost\r\n\r\n"), &mut auth);
        let server_state = start.lines().find(|line| line.starts_with("Location: ")).unwrap().split("state=").nth(1).unwrap();
        assert_ne!(server_state, flutter_state);
        let callback = super::response_for_request_with_auth(&format!("GET /oauth/google/callback?code=provider-code&state={server_state} HTTP/1.1\r\nHost: localhost\r\n\r\n"), &mut auth);
        let location = callback.lines().find(|line| line.starts_with("Location: ")).unwrap().strip_prefix("Location: ").unwrap();
        assert!(location.starts_with(app_callback));
        let query = location.split('?').nth(1).unwrap();
        let params: std::collections::HashMap<_, _> = query.split('&').filter_map(|pair| pair.split_once('=')).collect();
        let handoff = params.get("handoff").unwrap();
        let exchange = format!("GET /auth/session/bridge?handoff={handoff}&callback={app_callback}&state={flutter_state} HTTP/1.1\r\nHost: localhost\r\n\r\n");
        let response = super::response_for_request_with_auth(&exchange, &mut auth);
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(!response.contains("access-secret") && !response.contains("id-secret"));
    }

    #[test]
    fn auth_start_is_exposed_by_the_loopback_tcp_server() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(|| super::serve_with_auth(listener, Box::new(auth_service())).unwrap());
        let mut stream = std::net::TcpStream::connect(address).unwrap();
        stream.write_all(b"GET /oauth/google/start HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 302 Found"), "{response}");
    }

    #[test]
    fn auth_adapter_rejects_non_loopback_and_malformed_queries() {
        let mut auth = auth_service();
        assert!(super::response_for_request_with_auth("GET /oauth/google/start HTTP/1.1\r\nHost: example.test\r\n\r\n", &mut auth).starts_with("HTTP/1.1 403 Forbidden"));
        assert!(super::response_for_request_with_auth("GET /oauth/google/callback?state=%ZZ&code=x HTTP/1.1\r\nHost: localhost\r\n\r\n", &mut auth).starts_with("HTTP/1.1 400 Bad Request"));
    }

    #[test]
    fn auth_adapter_fails_closed_when_unconfigured() {
        for request in [
            "GET /oauth/google/start HTTP/1.1\r\nHost: localhost\r\n\r\n",
            "GET /oauth/google/callback?code=x&state=y HTTP/1.1\r\nHost: localhost\r\n\r\n",
            "GET /auth/session HTTP/1.1\r\nHost: localhost\r\n\r\n",
            "GET /auth/session/bridge?handoff=x&callback=http%3A%2F%2F127.0.0.1%3A1234%2Foauth%2Fcallback&state=y HTTP/1.1\r\nHost: localhost\r\n\r\n",
            "POST /auth/logout HTTP/1.1\r\nHost: localhost\r\n\r\n",
        ] {
            assert!(super::response_for_request(request).starts_with("HTTP/1.1 503 Service Unavailable"));
        }
    }


    #[test]
    fn version_endpoint_returns_local_scale_version() {
        let response = super::response_for_request("GET /version HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\"version\":\"0.1.0\""));
    }

    #[test]
    fn mode_endpoint_rejects_non_loopback_host() {
        let response = super::response_for_request("GET /mode HTTP/1.1\r\nHost: example.test\r\n\r\n");
        assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
    }

    #[test]
    fn mode_endpoint_accepts_client_mode() {
        let response = super::response_for_request("POST /mode HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 17\r\n\r\n{\"mode\":\"client\"}");
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\"mode\":\"client\""));
    }

    #[test]
    fn control_page_status_contract_defaults_to_cliente_stopped() {
        let response = super::response_for_request("GET /api/v1/status HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(response.contains(r#""mode":"cliente""#));
        assert!(response.contains(r#""state":"stopped""#));
        assert!(response.contains(r#""onion_endpoint":null"#));
    }

    #[test]
    fn control_page_routes_return_service_status_and_cliente_is_accepted() {
        let state = super::AgentState::default();
        let mode = super::response_for_request_with_state(
            "POST /api/v1/mode HTTP/1.1\r\nHost: localhost\r\n\r\n{\"mode\":\"host\"}", &state);
        assert!(mode.starts_with("HTTP/1.1 200 OK"), "{mode}");
        assert!(mode.contains(r#""mode":"host""#));
        assert!(mode.contains(r#""state":"stopped""#));

        let start = super::response_for_request_with_state(
            "POST /api/v1/service/start HTTP/1.1\r\nHost: localhost\r\n\r\n", &state);
        assert!(start.contains(r#""state":"running""#));
        let status = super::response_for_request_with_state(
            "GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\n\r\n", &state);
        assert!(status.contains(r#""mode":"host""#));
        assert!(status.contains(r#""state":"running""#));
    }

    #[test]
    fn peer_config_routes_store_safe_host_and_cliente_contract_without_secret_leakage() {
        let hostname = "abcdefghijklmnopqrstuvwxabcdefghijklmnopqrstuvwxyz234567.onion";
        let secret = "secret-token-123456";
        let state = super::AgentState::default();
        let host = super::response_for_request_with_state(&format!(
            "POST /api/v1/peer/config HTTP/1.1\r\nHost: localhost\r\n\r\n{{\"role\":\"host\",\"node_id\":\"host-01\",\"onion_endpoint\":\"{hostname}\",\"invitation_secret\":\"{secret}\"}}"), &state);
        assert!(host.starts_with("HTTP/1.1 200 OK"), "{host}");
        assert!(host.contains("\"transport\":\"unavailable\""));
        assert!(!host.contains(secret));
        let status = super::response_for_request_with_state("GET /api/v1/peer/status HTTP/1.1\r\nHost: localhost\r\n\r\n", &state);
        assert!(status.contains(hostname));
        assert!(!status.contains(secret));
        let cliente = super::response_for_request_with_state(&format!(
            "POST /api/v1/peer/config HTTP/1.1\r\nHost: localhost\r\n\r\n{{\"role\":\"cliente\",\"node_id\":\"client-01\",\"host_node_id\":\"host-01\",\"onion_endpoint\":\"{hostname}\",\"invitation_secret\":\"{secret}\"}}"), &state);
        assert!(cliente.starts_with("HTTP/1.1 200 OK"), "{cliente}");
    }

    #[test]
    fn peer_config_rejects_invalid_onion_and_non_loopback_admin_requests() {
        let invalid = super::response_for_request("POST /api/v1/peer/config HTTP/1.1\r\nHost: localhost\r\n\r\n{\"role\":\"cliente\",\"node_id\":\"client-01\",\"host_node_id\":\"host-01\",\"onion_endpoint\":\"/var/lib/tor/hostname\",\"invitation_secret\":\"secret-token-123456\"}");
        assert!(invalid.starts_with("HTTP/1.1 400 Bad Request"), "{invalid}");
        let remote = super::response_for_request("GET /api/v1/peer/status HTTP/1.1\r\nHost: example.test\r\n\r\n");
        assert!(remote.starts_with("HTTP/1.1 403 Forbidden"), "{remote}");
    }

    #[test]
    fn missing_or_non_loopback_host_is_rejected() {
        for host in ["", "example.test"] {
            let request = if host.is_empty() {
                "GET /api/v1/status HTTP/1.1\r\n\r\n".to_string()
            } else {
                format!("GET /api/v1/status HTTP/1.1\r\nHost: {host}\r\n\r\n")
            };
            let response = super::response_for_request(&request);
            assert!(response.starts_with("HTTP/1.1 403 Forbidden"), "{host}: {response}");
        }
    }

    #[test]
    fn loopback_host_matching_is_case_insensitive_and_supports_ports() {
        for host in ["LOCALHOST:8765", "127.0.0.1:9", "[::1]:8765"] {
            let response = super::response_for_request(&format!(
                "GET /api/v1/status HTTP/1.1\r\nHost: {host}\r\n\r\n"));
            assert!(response.starts_with("HTTP/1.1 200 OK"), "{host}: {response}");
        }
    }

    #[test]
    fn malformed_mode_json_is_rejected() {
        let response = super::response_for_request(
            "POST /api/v1/mode HTTP/1.1\r\nHost: localhost\r\n\r\nnot-json{\"mode\":\"host\"}");
        assert!(response.starts_with("HTTP/1.1 400 Bad Request"), "{response}");

        let response = super::response_for_request(
            "POST /api/v1/mode HTTP/1.1\r\nHost: localhost\r\n\r\n{\"mode\":\"client\"}");
        assert!(response.starts_with("HTTP/1.1 400 Bad Request"), "{response}");
    }

    #[test]
    fn peer_store_persists_approval_and_revocation_without_status_secret() {
        let path = std::env::temp_dir().join(format!("localscale-peer-test-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut store = super::PeerStore::open(&path).unwrap();
        store.configure(super::PeerRecord { role: "cliente".into(), node_id: "client-01".into(), host_node_id: Some("host-01".into()), endpoint: "abc.onion".into(), invitation_secret: "secret-value".into(), approved: false, revoked: false }).unwrap();
        assert!(!super::PeerStore::open(&path).unwrap().record().unwrap().approved);
        store.set_approval(true).unwrap();
        let reloaded = super::PeerStore::open(&path).unwrap();
        assert!(reloaded.record().unwrap().approved);
        store.set_approval(false).unwrap();
        let revoked = super::PeerStore::open(&path).unwrap();
        assert!(revoked.record().unwrap().revoked);
        let state = super::AgentState { peer_store: Some(std::sync::Arc::new(std::sync::Mutex::new(revoked))), ..super::AgentState::default() };
        let status = super::response_for_request_with_state("GET /api/v1/peer/status HTTP/1.1\\r\\nHost: localhost\\r\\n\\r\\n", &state);
        assert!(!status.contains("secret-value"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn peer_store_rejects_malformed_startup_state() {
        let path = std::env::temp_dir().join(format!("localscale-peer-bad-{}.json", std::process::id()));
        std::fs::write(&path, "not-json").unwrap();
        assert!(super::PeerStore::open(&path).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn health_endpoint_returns_ok_json() {
        assert_eq!(health_response(), r#"{"status":"ok","service":"localscale"}"#);
    }

    #[test]
    fn mode_parser_accepts_json_whitespace_but_rejects_extra_fields_and_escapes() {
        for body in [" { \"mode\" : \"host\" } ", "{\n\t\"mode\":\"cliente\"\n}"] {
            let response = super::response_for_request(&format!(
                "POST /api/v1/mode HTTP/1.1\r\nHost: localhost\r\n\r\n{body}"));
            assert!(response.starts_with("HTTP/1.1 200 OK"), "{body}: {response}");
        }
        for body in ["{\"mode\":\"host\",\"other\":true}", "{\"mode\":\"ho\\u0073t\"}"] {
            let response = super::response_for_request(&format!(
                "POST /api/v1/mode HTTP/1.1\r\nHost: localhost\r\n\r\n{body}"));
            assert!(response.starts_with("HTTP/1.1 400 Bad Request"), "{body}: {response}");
        }
    }

    #[test]
    fn write_budget_is_remaining_after_reading() {
        let started = std::time::Instant::now();
        let total = std::time::Duration::from_secs(5);
        let after_reading = started + std::time::Duration::from_secs(3);
        assert_eq!(super::remaining_budget(started, total, after_reading), Some(std::time::Duration::from_secs(2)));
        assert_eq!(super::remaining_budget(started, total, started + total), None);
    }

    #[test]
    fn poisoned_state_lock_is_recovered_for_request_handling() {
        let state = super::AgentState::default();
        let mode = state.mode.clone();
        let _ = std::panic::catch_unwind(move || {
            let _guard = mode.lock().unwrap();
            panic!("poison test");
        });
        let response = super::response_for_request_with_state(
            "GET /mode HTTP/1.1\r\nHost: localhost\r\n\r\n", &state);
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(response.contains(r#""mode":"cliente""#));
    }

    #[test]
    fn server_survives_connection_errors_and_slow_clients() {
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || super::serve(listener).unwrap());
        let slow = TcpStream::connect(address).unwrap();
        thread::sleep(Duration::from_millis(50));
        let mut broken = TcpStream::connect(address).unwrap();
        broken.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n").unwrap();
        drop(broken);
        let mut fast = TcpStream::connect(address).unwrap();
        fast.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        fast.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        let mut response = String::new();
        fast.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        drop(slow);
    }

    #[test]
    fn slowloris_connection_has_a_total_deadline() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;
        use std::time::Duration;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || super::serve(listener).unwrap());
        let mut slow = std::net::TcpStream::connect(address).unwrap();
        slow.set_read_timeout(Some(Duration::from_secs(7))).unwrap();
        slow.write_all(b"G").unwrap();
        thread::sleep(Duration::from_secs(6));
        let mut response = Vec::new();
        let result = slow.read_to_end(&mut response);
        assert!(result.is_ok() || result.unwrap_err().kind() == std::io::ErrorKind::UnexpectedEof);
        assert!(response.is_empty(), "slow client unexpectedly got response: {response:?}");
    }

    #[test]
    fn connection_limit_rejects_excess_clients() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;
        use std::time::Duration;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || super::serve(listener).unwrap());
        let mut held = Vec::new();
        for _ in 0..super::MAX_CONNECTIONS {
            let mut stream = std::net::TcpStream::connect(address).unwrap();
            stream.write_all(b"G").unwrap();
            held.push(stream);
        }
        let mut excess = std::net::TcpStream::connect(address).unwrap();
        excess.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut response = String::new();
        excess.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 503 Service Unavailable"), "{response}");
    }

    #[test]
    fn configuration_page_has_product_title() {
        assert!(configuration_html().contains("<title>LocalScale</title>"));
    }
}
