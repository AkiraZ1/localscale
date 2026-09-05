use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use localscale_control_plane::{AuthRequest, AuthResponse};

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
    auth: Option<SharedAuth>,
}

impl Default for AgentState {
    fn default() -> Self {
        Self {
            mode: Arc::new(Mutex::new("cliente".to_string())),
            service_state: Arc::new(Mutex::new("stopped".to_string())),
            auth: None,
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
    let state = AgentState { auth, ..AgentState::default() };
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
        ("GET", "/diagnostics") => http_response("200 OK", "application/json", r#"{"service":"localscale","loopback":true,"external_network":false}"#),
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
    http_response("200 OK", "application/json", &format!(
        r#"{{"mode":"{mode}","state":"{service_state}","onion_endpoint":null}}"#))
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
