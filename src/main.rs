use localscale_agent::{serve, serve_with_auth, AuthHandler};
use localscale_control_plane::{
    google_oidc::{ClientSecretRef, GoogleOidcConfig, GoogleOidcProvider, HttpRequest, HttpResponse, HttpTransport, TransportError},
    AuthService,
};
use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;
use std::thread;

const CURL_MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const CURL_TIMEOUT_SECONDS: u64 = 5;

struct Options {
    port: u16,
    no_open: bool,
}

fn parse_args(args: &[String]) -> Result<Options, String> {
    let mut port = 8765;
    let mut no_open = false;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--no-open" => no_open = true,
            "--port" => {
                index += 1;
                let value = args.get(index).ok_or("--port requires a value")?;
                port = value.parse().map_err(|_| "--port must be a valid TCP port")?;
            }
            argument => return Err(format!("unknown argument: {argument}")),
        }
        index += 1;
    }
    Ok(Options { port, no_open })
}

/// A deliberately small HTTPS-only adapter around the system curl binary.
/// The request body, including the client secret during token exchange, is
/// always written to curl's stdin and never appears in its argument list.
struct CurlTransport;

impl HttpTransport for CurlTransport {
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let timeout = request.timeout.min(Duration::from_secs(CURL_TIMEOUT_SECONDS));
        let timeout_seconds = timeout.as_secs_f64().max(0.001).to_string();
        let mut child = Command::new("curl")
            .args([
                "--silent",
                "--show-error",
                "--request",
                request.method.as_str(),
                "--connect-timeout",
                timeout_seconds.as_str(),
                "--max-time",
                timeout_seconds.as_str(),
                "--header",
                "content-type: application/x-www-form-urlencoded",
                "--write-out",
                "\n%{http_code}",
                "--url",
                request.url.as_str(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| TransportError::Network)?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(request.body.as_bytes())
                .map_err(|_| TransportError::Network)?;
        }
        let mut output = Vec::new();
        let Some(mut stdout) = child.stdout.take() else {
            return Err(TransportError::Network);
        };
        let mut buffer = [0_u8; 8192];
        while output.len() <= CURL_MAX_RESPONSE_BYTES + 32 {
            let read = stdout.read(&mut buffer).map_err(|_| TransportError::Network)?;
            if read == 0 {
                break;
            }
            output.extend_from_slice(&buffer[..read]);
        }
        if output.len() > CURL_MAX_RESPONSE_BYTES + 32 {
            let _ = child.kill();
            let _ = child.wait();
            return Err(TransportError::Network);
        }
        let _ = child.wait();
        parse_curl_output(&output).ok_or(TransportError::Network)
    }
}

fn parse_curl_output(output: &[u8]) -> Option<HttpResponse> {
    let split = output.iter().rposition(|byte| *byte == b'\n')?;
    let status = std::str::from_utf8(&output[split + 1..]).ok()?.trim().parse::<u16>().ok()?;
    if !(100..=599).contains(&status) {
        return None;
    }
    let body = std::str::from_utf8(&output[..split]).ok()?.to_owned();
    (body.len() <= CURL_MAX_RESPONSE_BYTES).then_some(HttpResponse { status, body })
}

fn redirect_uri_matches_port(redirect_uri: &str, port: u16) -> bool {
    for prefix in ["http://127.0.0.1:", "http://localhost:"] {
        if let Some(rest) = redirect_uri.strip_prefix(prefix) {
            let port_text = rest.split('/').next().unwrap_or("");
            return port_text.parse::<u16>().ok() == Some(port);
        }
    }
    true
}

fn auth_provider(port: u16) -> Option<Box<dyn AuthHandler>> {
    let secret = env::var("LOCALSCALE_GOOGLE_CLIENT_SECRET").ok().filter(|v| !v.is_empty())?;
    let redirect = env::var("LOCALSCALE_GOOGLE_REDIRECT_URI").ok()?;
    if !redirect_uri_matches_port(&redirect, port) {
        return None;
    }
    let config = GoogleOidcConfig::from_env(ClientSecretRef::new(secret)).ok()?;
    Some(Box::new(AuthService::new(
        GoogleOidcProvider::new(config, CurlTransport),
        Duration::from_secs(300),
        &redirect,
    )))
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let options = parse_args(&args).map_err(std::io::Error::other)?;
    let listener = TcpListener::bind(("127.0.0.1", options.port))?;
    let address = listener.local_addr()?;
    let url = format!("http://{address}/");
    println!("LocalScale web: {url}");

    let auth = auth_provider(address.port());
    let server = thread::spawn(move || match auth {
        Some(auth) => serve_with_auth(listener, auth),
        None => serve(listener),
    });
    wait_until_healthy(address)?;
    if !options.no_open {
        open_browser(&url);
    }
    server.join().map_err(|_| std::io::Error::other("LocalScale server thread failed"))?
}

fn wait_until_healthy(address: std::net::SocketAddr) -> std::io::Result<()> {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(100)) {
            stream.set_read_timeout(Some(Duration::from_millis(500)))?;
            stream.write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")?;
            let mut response = String::new();
            stream.read_to_string(&mut response)?;
            if health_response_is_ready(&response) { return Ok(()); }
        }
        if std::time::Instant::now() >= deadline {
            return Err(std::io::Error::other("LocalScale health check failed"));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn health_response_is_ready(response: &str) -> bool {
    response.starts_with("HTTP/1.1 200 OK")
        && response.contains("\r\n\r\n{\"status\":\"ok\"")
}

fn open_browser(url: &str) {
    #[cfg(target_os = "linux")]
    let command = ("xdg-open", vec![url]);
    #[cfg(target_os = "macos")]
    let command = ("open", vec![url]);
    #[cfg(target_os = "windows")]
    let command = ("cmd", vec!["/C", "start", "", url]);

    let _ = Command::new(command.0)
        .args(command.1)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    fn clear_auth_env() {
        for name in [
            "LOCALSCALE_GOOGLE_CLIENT_SECRET",
            "LOCALSCALE_GOOGLE_CLIENT_ID",
            "LOCALSCALE_OIDC_AUDIENCE",
            "LOCALSCALE_OIDC_ISSUER",
            "LOCALSCALE_GOOGLE_REDIRECT_URI",
            "LOCALSCALE_OIDC_SCOPES",
        ] {
            env::remove_var(name);
        }
    }

    #[test]
    fn readiness_requires_the_health_json_body() {
        assert!(!super::health_response_is_ready("HTTP/1.1 200 OK\r\n\r\n{}"));
        assert!(super::health_response_is_ready(
            "HTTP/1.1 200 OK\r\n\r\n{\"status\":\"ok\",\"service\":\"localscale\"}"));
    }

    #[test]
    fn arguments_support_port_and_no_open() {
        let options = super::parse_args(&["localscaled".into(), "--port".into(), "9123".into(), "--no-open".into()]).unwrap();
        assert_eq!(options.port, 9123);
        assert!(options.no_open);
    }

    #[test]
    fn missing_auth_config_keeps_auth_disabled() {
        let _guard = env_lock();
        clear_auth_env();
        assert!(auth_provider(8765).is_none());
    }

    #[test]
    fn complete_auth_config_bootstraps_provider() {
        let _guard = env_lock();
        clear_auth_env();
        env::set_var("LOCALSCALE_GOOGLE_CLIENT_SECRET", "test-placeholder-only");
        env::set_var("LOCALSCALE_GOOGLE_CLIENT_ID", "client-id");
        env::set_var("LOCALSCALE_OIDC_ISSUER", "https://accounts.google.com");
        env::set_var("LOCALSCALE_GOOGLE_REDIRECT_URI", "http://127.0.0.1:8765/oauth/google/callback");
        env::set_var("LOCALSCALE_OIDC_SCOPES", "openid email");
        assert!(auth_provider(8765).is_some());
        clear_auth_env();
    }

    #[test]
    fn explicit_loopback_redirect_must_match_port() {
        assert!(!redirect_uri_matches_port("http://127.0.0.1:9999/auth/google/callback", 8765));
        assert!(redirect_uri_matches_port("https://login.example.test/callback", 8765));
    }

    #[test]
    fn curl_output_parsing_is_bounded_and_preserves_status() {
        let response = parse_curl_output(b"{\"error\":\"bad\"}\n401").unwrap();
        assert_eq!(response.status, 401);
        assert_eq!(response.body, "{\"error\":\"bad\"}");
        assert!(parse_curl_output(b"not-a-response").is_none());
        assert!(parse_curl_output(&vec![b'x'; CURL_MAX_RESPONSE_BYTES + 1]).is_none());
    }
}
