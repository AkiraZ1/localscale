#[cfg(target_os = "linux")]
mod tun_linux;

use localscale_agent::tor_runtime::{resolve_bundled_tor, TorMode, TorProcess, TorRuntime};
use localscale_agent::{
    log_event, serve_with_auth_and_peer_transport, AuthHandler, PeerStore, PeerTransportStatus,
    RoleStore, TransportState,
};
use localscale_agent_protocol::{ClientConfig, HostInvitation};
use localscale_agent_transport::{
    key_from_stored_transport_key, ClienteTransport, FileNonceAllocator, HostTransport,
    PacketChannel, TorRuntime as PeerTorRuntime,
};
use localscale_control_plane::{
    google_oidc::{
        ClientSecretRef, GoogleOidcConfig, GoogleOidcProvider, HttpRequest, HttpResponse,
        HttpTransport, TransportError,
    },
    AuthService,
};
use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;

const CURL_MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const CURL_TIMEOUT_SECONDS: u64 = 5;
const TOR_READY_TIMEOUT: Duration = Duration::from_secs(300);
/// A supervisor can distinguish a requested configuration reload from an
/// ordinary failure. Standalone desktop startup observes the health drop and
/// launches the bundled agent again.
const RUNTIME_RESTART_EXIT_CODE: i32 = 75;

#[derive(Debug)]
struct RuntimeConfig {
    mode: TorMode,
    data_dir: std::path::PathBuf,
}

impl RuntimeConfig {
    fn data_dir_from_environment() -> Result<std::path::PathBuf, String> {
        let data_dir = env::var_os("LOCALSCALE_TOR_DATA_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                env::var_os("XDG_STATE_HOME")
                    .map(std::path::PathBuf::from)
                    .or_else(|| {
                        env::var_os("HOME")
                            .map(|home| std::path::PathBuf::from(home).join(".local/state"))
                    })
                    .unwrap_or_else(env::temp_dir)
                    .join("localscale/tor")
            });
        if !data_dir.is_absolute() {
            return Err("LOCALSCALE_TOR_DATA_DIR must be absolute".into());
        }
        Ok(data_dir)
    }

    fn from_environment() -> Result<Option<Self>, String> {
        let data_dir = Self::data_dir_from_environment()?;
        let role = env::var("LOCALSCALE_ROLE").ok();
        if let Some(role) = role {
            return Self::from_values_with_data_dir(
                Some(&role),
                env::var("LOCALSCALE_SERVICE_PORT").ok().as_deref(),
                env::var("LOCALSCALE_UPSTREAM").ok().as_deref(),
                env::var("LOCALSCALE_ONION_ENDPOINT").ok().as_deref(),
                data_dir,
            )
            .map(Some);
        }

        let store_path = env::var_os("LOCALSCALE_PEER_STORE")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| data_dir.join("peer-record.json"));
        let role_store_path = env::var_os("LOCALSCALE_ROLE_STORE")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| store_path.with_file_name("selected-role"));
        let store = match PeerStore::open(store_path) {
            Ok(store) => store,
            Err(error) => {
                eprintln!("LocalScale peer bootstrap disabled: invalid peer store ({error})");
                log_event(&format!("peer bootstrap disabled: invalid peer store ({error})"));
                return Ok(None);
            }
        };
        let selected_role = RoleStore::open(role_store_path)
            .map_err(|error| format!("invalid selected role: {error}"))?
            .role()
            .map(str::to_owned);
        let Some(record) = store.record() else {
            return match selected_role.as_deref() {
                Some("host") => Self::from_values_with_data_dir(
                    Some("host"),
                    Some(
                        env::var("LOCALSCALE_SERVICE_PORT")
                            .as_deref()
                            .unwrap_or("8765"),
                    ),
                    Some(
                        env::var("LOCALSCALE_UPSTREAM")
                            .as_deref()
                            .unwrap_or("127.0.0.1:8766"),
                    ),
                    None,
                    data_dir,
                )
                .map(Some),
                _ => Ok(None),
            };
        };
        if !record.approved || record.revoked {
            return Ok(None);
        }
        match Self::from_peer_record(record, data_dir) {
            Ok(config) => Ok(Some(config)),
            Err(error) => {
                eprintln!("LocalScale peer bootstrap disabled: invalid approved peer configuration ({error})");
                log_event(&format!("peer bootstrap disabled: invalid approved peer configuration ({error})"));
                Ok(None)
            }
        }
    }

    fn from_peer_record(
        record: &localscale_agent::PeerRecord,
        data_dir: std::path::PathBuf,
    ) -> Result<Self, String> {
        validate_approved_peer_record(record, &record.role)?;
        let mode = match record.role.as_str() {
            "host" => {
                let port = env::var("LOCALSCALE_SERVICE_PORT")
                    .ok()
                    .map(|value| {
                        value.parse::<u16>().map_err(|_| {
                            "LOCALSCALE_SERVICE_PORT must be a valid TCP port".to_string()
                        })
                    })
                    .transpose()?
                    .unwrap_or(8765);
                if port == 0 {
                    return Err("LOCALSCALE_SERVICE_PORT must be non-zero".into());
                }
                let upstream =
                    env::var("LOCALSCALE_UPSTREAM").unwrap_or_else(|_| "127.0.0.1:8766".into());
                TorMode::host(port, upstream).map_err(|e| e.to_string())?
            }
            "cliente" => TorMode::client(&record.endpoint).map_err(|e| e.to_string())?,
            other => {
                return Err(format!(
                    "peer record role must be host or cliente, got {other}"
                ))
            }
        };
        Ok(Self { mode, data_dir })
    }

    #[cfg(test)]
    fn from_values(
        role: Option<&str>,
        service_port: Option<&str>,
        upstream: Option<&str>,
        hostname: Option<&str>,
    ) -> Result<Self, String> {
        Self::from_values_with_data_dir(
            role,
            service_port,
            upstream,
            hostname,
            Self::data_dir_from_environment()?,
        )
    }

    fn from_values_with_data_dir(
        role: Option<&str>,
        service_port: Option<&str>,
        upstream: Option<&str>,
        hostname: Option<&str>,
        data_dir: std::path::PathBuf,
    ) -> Result<Self, String> {
        let mode = match role {
            Some("host") => {
                let port = service_port
                    .ok_or("host requires LOCALSCALE_SERVICE_PORT")?
                    .parse::<u16>()
                    .map_err(|_| "LOCALSCALE_SERVICE_PORT must be a valid TCP port")?;
                if port == 0 {
                    return Err("LOCALSCALE_SERVICE_PORT must be non-zero".into());
                }
                TorMode::host(port, upstream.ok_or("host requires LOCALSCALE_UPSTREAM")?)
                    .map_err(|e| e.to_string())?
            }
            Some("cliente") => {
                if service_port.is_some() {
                    return Err("cliente must not configure LOCALSCALE_SERVICE_PORT".into());
                }
                TorMode::client(hostname.ok_or("cliente requires LOCALSCALE_ONION_ENDPOINT")?)
                    .map_err(|e| e.to_string())?
            }
            Some(other) => {
                return Err(format!(
                    "LOCALSCALE_ROLE must be host or cliente, got {other}"
                ))
            }
            None => return Err("LOCALSCALE_ROLE is required; refusing an implicit role".into()),
        };
        Ok(Self { mode, data_dir })
    }
}

fn validate_approved_peer_record(
    record: &localscale_agent::PeerRecord,
    expected_role: &str,
) -> Result<(), String> {
    if !record.approved
        || record.revoked
        || !matches!(expected_role, "host" | "cliente")
        || record.role != expected_role
    {
        return Err("peer record is not approved or has an invalid role".into());
    }
    key_from_stored_transport_key(&record.invitation_secret)
        .map_err(|_| "peer record contains an invalid transport key".to_string())?;
    match expected_role {
        "host" => {
            if record.host_node_id.is_some() {
                return Err("host peer must not contain host_node_id".into());
            }
            HostInvitation::new(&record.node_id, &record.endpoint, "validation-secret-0001")
                .map_err(|e| format!("invalid host peer record: {e:?}"))?;
        }
        "cliente" => {
            let host_node_id = record
                .host_node_id
                .as_deref()
                .ok_or("cliente peer requires host_node_id")?;
            if host_node_id == record.node_id {
                return Err("peer node IDs must differ".into());
            }
            ClientConfig::client(
                &record.node_id,
                host_node_id,
                &record.endpoint,
                "validation-secret-0001",
            )
            .map_err(|e| format!("invalid cliente peer record: {e:?}"))?;
        }
        _ => unreachable!(),
    }
    Ok(())
}

struct RunningTor {
    process: TorProcess,
}

struct ProcessTorRuntime {
    socks: std::net::SocketAddr,
}
impl PeerTorRuntime for ProcessTorRuntime {
    fn socks_endpoint(&self) -> Option<std::net::SocketAddr> {
        Some(self.socks)
    }
    fn is_ready(&self) -> bool {
        true
    }
}

fn start_tor(bundle_root: &std::path::Path, config: &RuntimeConfig) -> Result<RunningTor, String> {
    let executable = resolve_bundled_tor(bundle_root).map_err(|e| e.to_string())?;
    let mut process = TorRuntime::new(executable, config.data_dir.clone())
        .map_err(|e| e.to_string())?
        .spawn(&config.mode)
        .map_err(|e| e.to_string())?;
    if let Err(error) = process.wait_for_readiness(TOR_READY_TIMEOUT) {
        let _ = process.terminate();
        return Err(error.to_string());
    }
    process.drain_log_into(|line| log_event(&format!("tor: {line}")));
    Ok(RunningTor { process })
}

fn wait_for_socks(endpoint: std::net::SocketAddr, timeout: Duration) -> Result<(), String> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match TcpStream::connect_timeout(&endpoint, Duration::from_millis(250)) {
            Ok(_) => return Ok(()),
            Err(_) if std::time::Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(100))
            }
            Err(_) => return Err("bundled Tor SOCKS endpoint did not become available".into()),
        }
    }
}

fn stop_tor(mut running: RunningTor) {
    let _ = running.process.terminate();
}

fn retry_delay(failures: u32) -> Duration {
    Duration::from_secs(1u64 << failures.saturating_sub(1).min(5))
}

/// Bridges a live `PacketChannel` to a real TUN network interface: one
/// thread copies packets read off the interface onto the peer connection,
/// another writes whatever the peer sends back onto the interface. This is
/// what turns the virtual IPs the two sides already exchange (see
/// `PeerTransportStatus`) into an actual routable link between them, instead
/// of being informational only.
///
/// Gated behind `LOCALSCALE_ENABLE_TUN=1` (see `start_peer_transport`) and,
/// for now, only implemented for Linux — macOS (`utun`) and Windows
/// (Wintun) are follow-up work using the same `PacketChannel` this already
/// plugs into; on any other platform this logs once and does nothing, so
/// enabling the flag elsewhere is a safe no-op rather than a build error.
#[cfg(target_os = "linux")]
fn spawn_tun_bridge(status: &PeerTransportStatus, packets: PacketChannel) {
    let local_ip = status.local_virtual_ip();
    if local_ip.is_empty() {
        log_event("tun: no local virtual IP configured, skipping TUN bridge");
        return;
    }
    let device = match tun_linux::TunDevice::create("localscale0") {
        Ok(device) => device,
        Err(error) => {
            log_event(&format!(
                "tun: failed to create TUN device (needs CAP_NET_ADMIN — see scripts/install-linux.sh): {error}"
            ));
            return;
        }
    };
    if let Err(error) = device.configure_address(&format!("{local_ip}/24")) {
        log_event(&format!("tun: failed to configure {}: {error}", device.name()));
        return;
    }
    log_event(&format!(
        "tun: {} up with {local_ip}/24 — bridging to peer",
        device.name()
    ));
    // The peer's virtual IP may not be known yet (learned from its first
    // heartbeat); poll briefly rather than failing the whole bridge if the
    // route can't be added the instant the interface comes up.
    {
        let device_for_route = device.file().try_clone();
        let status = status.clone();
        let name = device.name().to_string();
        if device_for_route.is_ok() {
            std::thread::spawn(move || {
                for _ in 0..20 {
                    if let Some(peer_ip) = status.remote_virtual_ip() {
                        if !peer_ip.is_empty() {
                            let _ = tun_linux::TunDevice::route_to_peer(&name, &peer_ip);
                            return;
                        }
                    }
                    thread::sleep(Duration::from_secs(1));
                }
            });
        }
    }
    let mut reader_file = match device.file().try_clone() {
        Ok(file) => file,
        Err(error) => {
            log_event(&format!("tun: failed to clone TUN handle: {error}"));
            return;
        }
    };
    let mut writer_file = match device.file().try_clone() {
        Ok(file) => file,
        Err(error) => {
            log_event(&format!("tun: failed to clone TUN handle: {error}"));
            return;
        }
    };
    // TUN device → peer: read whatever the kernel hands back from this
    // interface and forward it as a packet frame.
    let sender = packets.sender();
    std::thread::spawn(move || {
        let mut buf = [0u8; 65535];
        loop {
            let n = match reader_file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            if sender.send_packet(&buf[..n]).is_err() {
                break;
            }
        }
    });
    // Peer → TUN device: whatever the peer forwards gets written straight
    // back onto the interface for the kernel to route locally. This thread
    // exits on its own once `receive_packet` starts erroring — which
    // happens once the demultiplexing reader thread inside
    // `AuthenticatedStream::into_multiplexed` exits and drops its sender,
    // i.e. once the underlying connection itself is gone — so it needs no
    // separate shutdown signal.
    std::thread::spawn(move || loop {
        match packets.receive_packet(Duration::from_secs(30)) {
            Ok(packet) => {
                if writer_file.write_all(&packet).is_err() {
                    break;
                }
            }
            Err(localscale_agent_transport::TransportError::Timeout) => continue,
            Err(_) => break,
        }
    });
    // Keep the device alive for the process's lifetime by leaking it: it
    // must stay open as long as either forwarding thread holds a cloned fd.
    std::mem::forget(device);
}

#[cfg(not(target_os = "linux"))]
fn spawn_tun_bridge(_status: &PeerTransportStatus, packets: PacketChannel) {
    log_event("tun: LOCALSCALE_ENABLE_TUN is set but this platform has no TUN implementation yet (Linux only so far)");
    // Nothing reads `receive_packet` on this platform; if the peer has TUN
    // enabled and starts forwarding real traffic, its packets would pile up
    // forever in the channel's internal queue with no consumer. Drain and
    // discard them so enabling the flag on an unsupported platform degrades
    // to "no network," not a slow memory leak.
    std::thread::spawn(move || {
        while packets.receive_packet(Duration::from_secs(3600)).is_ok() {}
    });
}

fn start_peer_transport(
    config: &RuntimeConfig,
    tor: &RunningTor,
    gate: Arc<AtomicBool>,
    status: PeerTransportStatus,
) -> Result<(), String> {
    let store_path = env::var_os("LOCALSCALE_PEER_STORE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| config.data_dir.join("peer-record.json"));
    if env::var_os("LOCALSCALE_PEER_STORE").is_none() {
        env::set_var("LOCALSCALE_PEER_STORE", &store_path);
    }
    let store = PeerStore::open(&store_path).map_err(|e| format!("peer store unavailable: {e}"))?;
    let record = store
        .record()
        .ok_or("peer is not configured; refusing transport startup")?;
    let expected_role = match &config.mode {
        TorMode::Host { .. } => "host",
        TorMode::Client { .. } => "cliente",
    };
    validate_approved_peer_record(record, expected_role)?;
    let key = key_from_stored_transport_key(&record.invitation_secret)
        .map_err(|_| "peer record contains an invalid transport key".to_string())?;
    let nonce_path = config.data_dir.join("handshake-nonce");
    // Off by default: the ping/pong path above this feature flag is the
    // proven, stable connection users depend on today. The TUN datapath is
    // new, Linux-only so far (see `tun_linux`), and only ever activates when
    // explicitly requested, so it can be developed and tested without any
    // risk of regressing ordinary pairing.
    let tun_enabled = env::var("LOCALSCALE_ENABLE_TUN").as_deref() == Ok("1");
    match &config.mode {
        TorMode::Host { upstream, .. } => {
            let address: std::net::SocketAddr = upstream
                .parse()
                .map_err(|_| "host upstream must be a socket address".to_string())?;
            let allocator = FileNonceAllocator::open(nonce_path).map_err(|e| e.to_string())?;
            let mut host =
                HostTransport::bind(address, key, record.node_id.clone(), Box::new(allocator))
                    .map_err(|e| e.to_string())?;
            host.set_acceptance_gate(gate.clone());
            let host_status = status.clone();
            let local_node_id = record.node_id.clone();
            host_status.set_local_virtual_ip(record.virtual_ip.clone().unwrap_or_default());
            std::thread::spawn(move || loop {
                host_status.set(TransportState::Connecting);
                match host.accept() {
                    Ok(stream) => {
                        // The handshake authenticates the connecting Cliente's real
                        // node id (see `AuthenticatedStream::peer_node_id`); record it
                        // so `devices_status()` can show it instead of a generic
                        // "remote-client" placeholder that never changed.
                        host_status.set_remote_node_id(stream.peer_node_id().to_string());
                        let (heartbeat, packets) = stream.into_multiplexed();
                        if tun_enabled {
                            spawn_tun_bridge(&host_status, packets);
                        }
                        while gate.load(Ordering::Acquire) {
                            match heartbeat.receive_ping(localscale_agent_transport::DEFAULT_TIMEOUT) {
                                Ok((sequence, peer_virtual_ip)) => {
                                    host_status.set_remote_virtual_ip(peer_virtual_ip);
                                    let local_virtual_ip = host_status.local_virtual_ip();
                                    if heartbeat
                                        .send_pong(&local_node_id, sequence, &local_virtual_ip)
                                        .is_err()
                                    {
                                        break;
                                    }
                                    // One authenticated ping received and one matching pong sent.
                                    host_status.record_peer_activity(2);
                                }
                                Err(error) => {
                                    eprintln!("LocalScale peer heartbeat failed: {error}");
                                    log_event(&format!("host: peer heartbeat failed: {error}"));
                                    break;
                                }
                            }
                        }
                    }
                    Err(error) => {
                        eprintln!("LocalScale peer handshake failed: {error}");
                        log_event(&format!("host: peer handshake failed: {error}"));
                        thread::sleep(Duration::from_secs(1));
                    }
                }
                host_status.set(TransportState::Retrying);
            });
            Ok(())
        }
        TorMode::Client { hostname } => {
            let host_node_id = record
                .host_node_id
                .clone()
                .ok_or("approved cliente peer lacks host node id")?;
            let port = env::var("LOCALSCALE_ONION_PORT")
                .ok()
                .map(|v| {
                    v.parse::<u16>()
                        .map_err(|_| "LOCALSCALE_ONION_PORT must be a valid TCP port".to_string())
                })
                .transpose()?
                .unwrap_or(8765);
            let allocator = FileNonceAllocator::open(nonce_path).map_err(|e| e.to_string())?;
            wait_for_socks(tor.process.socks_endpoint(), TOR_READY_TIMEOUT)?;
            let socks = tor.process.socks_endpoint();
            let node_id = record.node_id.clone();
            status.set_local_virtual_ip(record.virtual_ip.clone().unwrap_or_default());
            let hostname = hostname.clone();
            std::thread::spawn(move || {
                let mut client = ClienteTransport::new(
                    Box::new(ProcessTorRuntime { socks }),
                    key,
                    node_id.clone(),
                    host_node_id,
                    Box::new(allocator),
                );
                let mut failures: u32 = 0;
                loop {
                    if !gate.load(Ordering::Acquire) {
                        status.set(TransportState::Disabled);
                        thread::sleep(Duration::from_millis(250));
                        continue;
                    }
                    status.set(if failures == 0 {
                        TransportState::Connecting
                    } else {
                        TransportState::Retrying
                    });
                    match client.connect(&hostname, port) {
                        Ok(stream) => {
                            failures = 0;
                            let (heartbeat, packets) = stream.into_multiplexed();
                            if tun_enabled {
                                spawn_tun_bridge(&status, packets);
                            }
                            let mut sequence = 0u64;
                            while gate.load(Ordering::Acquire) {
                                sequence = sequence.wrapping_add(1);
                                let local_virtual_ip = status.local_virtual_ip();
                                if heartbeat
                                    .send_ping(&node_id, sequence, &local_virtual_ip)
                                    .is_err()
                                {
                                    break;
                                }
                                let peer_virtual_ip = match heartbeat.receive_pong(
                                    sequence,
                                    localscale_agent_transport::DEFAULT_TIMEOUT,
                                ) {
                                    Ok(peer_virtual_ip) => peer_virtual_ip,
                                    Err(_) => break,
                                };
                                status.set_remote_virtual_ip(peer_virtual_ip);
                                // One ping sent and its authenticated-session pong received.
                                status.record_peer_activity(2);
                                if sequence == 1 {
                                    println!("LocalScale peer: connected through bundled Tor");
                                    log_event("cliente: connected through bundled Tor");
                                }
                                thread::sleep(localscale_agent_transport::HEARTBEAT_INTERVAL);
                            }
                        }
                        Err(error) => {
                            eprintln!("LocalScale cliente connection attempt failed: {error}");
                            log_event(&format!("cliente: connection attempt failed: {error}"))
                        }
                    }
                    failures = failures.saturating_add(1);
                    status.set(if gate.load(Ordering::Acquire) {
                        TransportState::Retrying
                    } else {
                        TransportState::Disabled
                    });
                    thread::sleep(retry_delay(failures));
                }
            });
            Ok(())
        }
    }
}

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
                port = value
                    .parse()
                    .map_err(|_| "--port must be a valid TCP port")?;
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

fn curl_args(request: &HttpRequest, timeout_seconds: &str) -> Vec<String> {
    let mut args = vec![
        "--silent".into(),
        "--show-error".into(),
        "--request".into(),
        request.method.clone(),
        "--connect-timeout".into(),
        timeout_seconds.into(),
        "--max-time".into(),
        timeout_seconds.into(),
        "--header".into(),
        "content-type: application/x-www-form-urlencoded".into(),
        "--write-out".into(),
        "\n%{http_code}".into(),
    ];
    if request.method != "GET" && !request.body.is_empty() {
        args.extend(["--data-binary".into(), "@-".into()]);
    }
    args.extend(["--url".into(), request.url.clone()]);
    args
}

impl HttpTransport for CurlTransport {
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let timeout = request
            .timeout
            .min(Duration::from_secs(CURL_TIMEOUT_SECONDS));
        let timeout_seconds = timeout.as_secs_f64().max(0.001).to_string();
        let mut child = Command::new("curl")
            .args(curl_args(&request, &timeout_seconds))
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
            let read = stdout
                .read(&mut buffer)
                .map_err(|_| TransportError::Network)?;
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
    let status = std::str::from_utf8(&output[split + 1..])
        .ok()?
        .trim()
        .parse::<u16>()
        .ok()?;
    if !(100..=599).contains(&status) {
        return None;
    }
    let body = std::str::from_utf8(&output[..split]).ok()?.to_owned();
    (body.len() <= CURL_MAX_RESPONSE_BYTES).then_some(HttpResponse { status, body })
}

fn redirect_uri_matches_port(redirect_uri: &str, port: u16) -> bool {
    redirect_uri == format!("http://127.0.0.1:{port}/oauth/google/callback")
}

fn auth_provider(port: u16) -> Option<Box<dyn AuthHandler>> {
    let secret = env::var("LOCALSCALE_GOOGLE_CLIENT_SECRET")
        .ok()
        .filter(|v| !v.is_empty())?;
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
    // The control API and the bootstrap path must use the same durable peer
    // record. Without this, a first-run profile could be written to the
    // library's test-friendly ephemeral store and disappear before the
    // scheduled runtime reload.
    if env::var_os("LOCALSCALE_PEER_STORE").is_none() {
        let peer_store = RuntimeConfig::data_dir_from_environment()
            .map_err(std::io::Error::other)?
            .join("peer-record.json");
        env::set_var("LOCALSCALE_PEER_STORE", peer_store);
    }
    let peer_transport_enabled = Arc::new(AtomicBool::new(true));
    let peer_transport_status = PeerTransportStatus::default();
    let listener = TcpListener::bind(("127.0.0.1", options.port))?;
    let running_tor = match RuntimeConfig::from_environment().map_err(std::io::Error::other)? {
        Some(runtime_config) => {
            let bundle_root = env::var_os("LOCALSCALE_BUNDLE_ROOT")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| {
                    env::current_exe()
                        .ok()
                        .and_then(|path| path.parent().map(std::path::Path::to_path_buf))
                        .unwrap_or_else(|| std::path::PathBuf::from("/nonexistent"))
                });
            let running =
                start_tor(&bundle_root, &runtime_config).map_err(std::io::Error::other)?;
            let fresh_host = matches!(runtime_config.mode, TorMode::Host { .. })
                && PeerStore::open(
                    env::var_os("LOCALSCALE_PEER_STORE")
                        .expect("peer store path initialized before Tor startup"),
                )
                .ok()
                .is_some_and(|store| store.record().is_none());
            match start_peer_transport(
                &runtime_config,
                &running,
                peer_transport_enabled.clone(),
                peer_transport_status.clone(),
            ) {
                Ok(()) => Some(running),
                Err(error) => {
                    if fresh_host {
                        peer_transport_enabled.store(false, Ordering::Release);
                        peer_transport_status.set(TransportState::WaitingForInvitation);
                        eprintln!("LocalScale Host Onion is ready and waiting for an invitation");
                        log_event("host: Onion ready, waiting for an invitation");
                        Some(running)
                    } else {
                        eprintln!("LocalScale peer transport disabled: {error}");
                        log_event(&format!("peer transport disabled: {error}"));
                        stop_tor(running);
                        None
                    }
                }
            }
        }
        None => None,
    };
    let address = listener.local_addr()?;
    let url = format!("http://{address}/");
    println!("LocalScale web: {url}");

    let auth = auth_provider(address.port());
    let server = thread::spawn(move || match auth {
        Some(auth) => serve_with_auth_and_peer_transport(
            listener,
            auth,
            peer_transport_enabled,
            peer_transport_status,
        ),
        None => localscale_agent::serve_with_peer_transport(
            listener,
            peer_transport_enabled,
            peer_transport_status,
        ),
    });
    let result = wait_until_healthy(address).and_then(|_| {
        if !options.no_open {
            open_browser(&url);
        }
        server
            .join()
            .map_err(|_| std::io::Error::other("LocalScale server thread failed"))?
    });
    let restart_requested = matches!(
        result.as_ref().err(),
        Some(error) if error.kind() == std::io::ErrorKind::Interrupted
    );
    if let Some(running_tor) = running_tor {
        stop_tor(running_tor);
    }
    if restart_requested {
        std::process::exit(RUNTIME_RESTART_EXIT_CODE);
    }
    result
}

fn wait_until_healthy(address: std::net::SocketAddr) -> std::io::Result<()> {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(100)) {
            stream.set_read_timeout(Some(Duration::from_millis(500)))?;
            stream.write_all(
                b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            )?;
            let mut response = String::new();
            stream.read_to_string(&mut response)?;
            if health_response_is_ready(&response) {
                return Ok(());
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(std::io::Error::other("LocalScale health check failed"));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn health_response_is_ready(response: &str) -> bool {
    response.starts_with("HTTP/1.1 200 OK") && response.contains("\r\n\r\n{\"status\":\"ok\"")
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

    fn test_temp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("localscale-main-{name}-{}", std::process::id()))
    }

    #[cfg(unix)]
    fn fake_bundled_executable(root: &std::path::Path, exits: bool) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = root.join("tor/tor");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let starts = root.join("tor-starts");
        let script = if exits {
            format!(
                "#!/bin/sh\nprintf '%s\\n' $$ >> '{}'\n/bin/echo 'Bootstrapped 100%' >&2\nexit 0\n",
                starts.display()
            )
        } else {
            format!("#!/bin/sh\nprintf '%s\\n' $$ >> '{}'\n/bin/echo 'Bootstrapped 100%' >&2\ntrap 'exit 0' TERM INT\nwhile :; do /bin/sleep 1; done\n", starts.display())
        };
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[cfg(unix)]
    #[test]
    fn second_instance_binds_before_starting_tor() {
        let root = test_temp("duplicate-startup");
        let executable = fake_bundled_executable(&root, false);
        let config = RuntimeConfig {
            mode: TorMode::Client {
                hostname: format!("{}.onion", "a".repeat(56)),
            },
            data_dir: root.join("data"),
        };
        let port = TcpListener::bind(("127.0.0.1", 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let first_listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
        let mut first = start_tor(&root, &config).unwrap();
        assert!(first.process.try_exit().unwrap().is_none());

        let second_listener = TcpListener::bind(("127.0.0.1", port));
        assert!(second_listener.is_err());
        assert!(first.process.try_exit().unwrap().is_none());
        let starts = std::fs::read_to_string(root.join("tor-starts")).unwrap();
        assert_eq!(starts.lines().count(), 1);

        stop_tor(first);
        drop(first_listener);
        let _ = std::fs::remove_file(executable);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn runtime_config_selects_host_and_cliente_without_defaults() {
        let host =
            RuntimeConfig::from_values(Some("host"), Some("8080"), Some("127.0.0.1:8765"), None)
                .unwrap();
        assert_eq!(
            host.mode,
            TorMode::Host {
                service_port: 8080,
                upstream: "127.0.0.1:8765".into()
            }
        );
        let client = RuntimeConfig::from_values(
            Some("cliente"),
            None,
            None,
            Some(&format!("{}.onion", "a".repeat(56))),
        )
        .unwrap();
        assert!(matches!(client.mode, TorMode::Client { .. }));
        assert!(RuntimeConfig::from_values(None, None, None, None).is_err());
    }

    #[test]
    fn persisted_host_role_bootstraps_tor_before_first_invitation() {
        let _guard = env_lock();
        let root = test_temp("fresh-host-role");
        let peer_path = root.join("peer-record.json");
        let role_path = root.join("selected-role");
        let mut roles = RoleStore::open(&role_path).unwrap();
        assert!(roles.set("host").unwrap());
        env::remove_var("LOCALSCALE_ROLE");
        env::set_var("LOCALSCALE_PEER_STORE", &peer_path);
        env::set_var("LOCALSCALE_ROLE_STORE", &role_path);
        env::set_var("LOCALSCALE_TOR_DATA_DIR", root.join("tor"));
        env::remove_var("LOCALSCALE_SERVICE_PORT");
        env::remove_var("LOCALSCALE_UPSTREAM");
        let config = RuntimeConfig::from_environment().unwrap().unwrap();
        assert_eq!(
            config.mode,
            TorMode::Host {
                service_port: 8765,
                upstream: "127.0.0.1:8766".into(),
            }
        );
        env::remove_var("LOCALSCALE_PEER_STORE");
        env::remove_var("LOCALSCALE_ROLE_STORE");
        env::remove_var("LOCALSCALE_TOR_DATA_DIR");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn runtime_config_rejects_wrong_role_fields_and_invalid_ports() {
        assert!(
            RuntimeConfig::from_values(Some("host"), Some("0"), Some("127.0.0.1:8765"), None)
                .is_err()
        );
        assert!(RuntimeConfig::from_values(Some("cliente"), Some("8080"), None, None).is_err());
    }

    #[test]
    fn approved_peer_store_bootstraps_cliente_runtime_after_restart() {
        let _guard = env_lock();
        let path = test_temp("runtime-peer-client");
        let data_dir = test_temp("runtime-peer-client-data");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(&data_dir);
        let hostname = format!("{}.onion", "a".repeat(56));
        let mut store = PeerStore::open(&path).unwrap();
        store
            .configure(localscale_agent::PeerRecord {
                role: "cliente".into(),
                node_id: "client-01".into(),
                host_node_id: Some("host-01".into()),
                endpoint: hostname.clone(),
                invitation_secret: "secret-value-1234".into(),
                virtual_ip: None,
                approved: true,
                revoked: false,
            })
            .unwrap();
        env::set_var("LOCALSCALE_PEER_STORE", &path);
        env::set_var("LOCALSCALE_TOR_DATA_DIR", &data_dir);
        env::remove_var("LOCALSCALE_ROLE");
        env::remove_var("LOCALSCALE_ONION_ENDPOINT");
        env::remove_var("LOCALSCALE_SERVICE_PORT");
        env::remove_var("LOCALSCALE_UPSTREAM");

        let first_start = RuntimeConfig::from_environment().unwrap().unwrap();
        let second_start = RuntimeConfig::from_environment().unwrap().unwrap();
        assert_eq!(first_start.mode, TorMode::Client { hostname });
        assert_eq!(second_start.mode, first_start.mode);
        assert_eq!(second_start.data_dir, data_dir);

        for name in ["LOCALSCALE_PEER_STORE", "LOCALSCALE_TOR_DATA_DIR"] {
            env::remove_var(name);
        }
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn approved_peer_store_bootstraps_host_runtime_after_restart() {
        let _guard = env_lock();
        let path = test_temp("runtime-peer-host");
        let data_dir = test_temp("runtime-peer-host-data");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(&data_dir);
        let mut store = PeerStore::open(&path).unwrap();
        store
            .configure(localscale_agent::PeerRecord {
                role: "host".into(),
                node_id: "host-01".into(),
                host_node_id: None,
                endpoint: format!("{}.onion", "b".repeat(56)),
                invitation_secret: "secret-value-1234".into(),
                virtual_ip: None,
                approved: true,
                revoked: false,
            })
            .unwrap();
        env::set_var("LOCALSCALE_PEER_STORE", &path);
        env::set_var("LOCALSCALE_TOR_DATA_DIR", &data_dir);
        env::remove_var("LOCALSCALE_ROLE");
        env::remove_var("LOCALSCALE_SERVICE_PORT");
        env::remove_var("LOCALSCALE_UPSTREAM");

        let config = RuntimeConfig::from_environment().unwrap().unwrap();
        assert_eq!(
            config.mode,
            TorMode::Host {
                service_port: 8765,
                upstream: "127.0.0.1:8766".into()
            }
        );

        for name in ["LOCALSCALE_PEER_STORE", "LOCALSCALE_TOR_DATA_DIR"] {
            env::remove_var(name);
        }
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn semantically_invalid_approved_peer_store_fails_closed() {
        let _guard = env_lock();
        let path = test_temp("runtime-peer-invalid");
        let _ = std::fs::remove_file(&path);
        let mut store = PeerStore::open(&path).unwrap();
        store
            .configure(localscale_agent::PeerRecord {
                role: "unknown".into(),
                node_id: "node-01".into(),
                host_node_id: None,
                endpoint: "not-an-onion".into(),
                invitation_secret: "secret-value-1234".into(),
                virtual_ip: None,
                approved: true,
                revoked: false,
            })
            .unwrap();
        env::set_var("LOCALSCALE_PEER_STORE", &path);
        env::remove_var("LOCALSCALE_ROLE");
        assert!(RuntimeConfig::from_environment().unwrap().is_none());
        env::remove_var("LOCALSCALE_PEER_STORE");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn unapproved_peer_store_does_not_bootstrap_runtime() {
        let _guard = env_lock();
        let path = test_temp("runtime-peer-unapproved");
        let _ = std::fs::remove_file(&path);
        let mut store = PeerStore::open(&path).unwrap();
        store
            .configure(localscale_agent::PeerRecord {
                role: "cliente".into(),
                node_id: "client-01".into(),
                host_node_id: Some("host-01".into()),
                endpoint: format!("{}.onion", "a".repeat(56)),
                invitation_secret: "secret-value-1234".into(),
                virtual_ip: None,
                approved: false,
                revoked: false,
            })
            .unwrap();
        env::set_var("LOCALSCALE_PEER_STORE", &path);
        env::remove_var("LOCALSCALE_ROLE");
        assert!(RuntimeConfig::from_environment().unwrap().is_none());
        env::remove_var("LOCALSCALE_PEER_STORE");
        let _ = std::fs::remove_file(path);
    }

    fn approved_cliente_record() -> localscale_agent::PeerRecord {
        localscale_agent::PeerRecord {
            role: "cliente".into(),
            node_id: "client-01".into(),
            host_node_id: Some("host-01".into()),
            endpoint: format!("{}.onion", "a".repeat(56)),
            invitation_secret: "secret-value-1234".into(),
            virtual_ip: None,
            approved: true,
            revoked: false,
        }
    }

    #[test]
    fn approved_peer_validation_rejects_malformed_role() {
        let mut record = approved_cliente_record();
        record.role = "client".into();
        assert!(validate_approved_peer_record(&record, "cliente").is_err());
    }

    #[test]
    fn approved_peer_validation_rejects_malformed_node_ids() {
        let mut record = approved_cliente_record();
        record.node_id = "../client".into();
        assert!(validate_approved_peer_record(&record, "cliente").is_err());
        let mut record = approved_cliente_record();
        record.host_node_id = Some("host node".into());
        assert!(validate_approved_peer_record(&record, "cliente").is_err());
    }

    #[test]
    fn approved_peer_validation_requires_role_specific_host_node_id() {
        let mut record = approved_cliente_record();
        record.host_node_id = None;
        assert!(validate_approved_peer_record(&record, "cliente").is_err());
        let mut host = approved_cliente_record();
        host.role = "host".into();
        host.node_id = "host-01".into();
        host.host_node_id = Some("host-01".into());
        assert!(validate_approved_peer_record(&host, "host").is_err());
    }

    #[test]
    fn approved_peer_validation_rejects_non_public_onion_endpoint() {
        let mut record = approved_cliente_record();
        record.endpoint = "127.0.0.1:8765".into();
        assert!(validate_approved_peer_record(&record, "cliente").is_err());
    }

    #[test]
    fn approved_peer_validation_rejects_malformed_invitation_secret() {
        let mut record = approved_cliente_record();
        record.invitation_secret = "too-short".into();
        assert!(validate_approved_peer_record(&record, "cliente").is_err());
        record.invitation_secret = "secret with spaces-123".into();
        assert!(validate_approved_peer_record(&record, "cliente").is_err());
    }

    #[test]
    fn approved_peer_validation_rejects_revoked_record_before_bootstrap() {
        let mut record = approved_cliente_record();
        record.revoked = true;
        assert!(validate_approved_peer_record(&record, "cliente").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn lifecycle_starts_fake_bundled_tor_and_kills_it_cleanly() {
        let root = test_temp("lifecycle");
        let executable = fake_bundled_executable(&root, false);
        let config = RuntimeConfig {
            mode: TorMode::Client {
                hostname: format!("{}.onion", "a".repeat(56)),
            },
            data_dir: root.join("data"),
        };
        let mut runtime = start_tor(&root, &config).unwrap();
        assert!(runtime.process.try_exit().unwrap().is_none());
        stop_tor(runtime);
        let _ = std::fs::remove_file(executable);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn lifecycle_fails_closed_when_bundle_is_absent() {
        let root = test_temp("missing-bundle");
        std::fs::create_dir_all(&root).unwrap();
        let config = RuntimeConfig {
            mode: TorMode::Client {
                hostname: format!("{}.onion", "a".repeat(56)),
            },
            data_dir: root.join("data"),
        };
        assert!(start_tor(&root, &config).is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn readiness_requires_the_health_json_body() {
        assert!(!super::health_response_is_ready(
            "HTTP/1.1 200 OK\r\n\r\n{}"
        ));
        assert!(super::health_response_is_ready(
            "HTTP/1.1 200 OK\r\n\r\n{\"status\":\"ok\",\"service\":\"localscale\"}"
        ));
    }

    #[test]
    fn arguments_support_port_and_no_open() {
        let options = super::parse_args(&[
            "localscaled".into(),
            "--port".into(),
            "9123".into(),
            "--no-open".into(),
        ])
        .unwrap();
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
        env::set_var(
            "LOCALSCALE_GOOGLE_REDIRECT_URI",
            "http://127.0.0.1:8765/oauth/google/callback",
        );
        env::set_var("LOCALSCALE_OIDC_SCOPES", "openid email");
        assert!(auth_provider(8765).is_some());
        clear_auth_env();
    }

    #[test]
    fn runtime_redirect_must_be_exact_bound_loopback_callback() {
        assert!(redirect_uri_matches_port(
            "http://127.0.0.1:8765/oauth/google/callback",
            8765
        ));
        for redirect in [
            "http://127.0.0.1:9999/oauth/google/callback",
            "http://127.0.0.1:8765/oauth/callback",
            "http://localhost:8765/oauth/google/callback",
            "https://127.0.0.1:8765/oauth/google/callback",
            "https://login.example.test/callback",
        ] {
            assert!(
                !redirect_uri_matches_port(redirect, 8765),
                "accepted invalid redirect {redirect}"
            );
        }
    }

    #[test]
    fn auth_bootstrap_rejects_non_loopback_and_wrong_path_redirects() {
        let _guard = env_lock();
        for redirect in [
            "https://login.example.test/callback",
            "http://127.0.0.1:8765/oauth/callback",
            "http://127.0.0.1:8765/",
        ] {
            clear_auth_env();
            env::set_var("LOCALSCALE_GOOGLE_CLIENT_SECRET", "test-placeholder-only");
            env::set_var("LOCALSCALE_GOOGLE_CLIENT_ID", "client-id");
            env::set_var("LOCALSCALE_OIDC_ISSUER", "https://accounts.google.com");
            env::set_var("LOCALSCALE_GOOGLE_REDIRECT_URI", redirect);
            assert!(
                auth_provider(8765).is_none(),
                "bootstrapped invalid redirect {redirect}"
            );
        }
        clear_auth_env();
    }

    #[test]
    fn post_curl_arguments_read_body_from_stdin_without_exposing_it() {
        let request = HttpRequest {
            method: "POST".into(),
            url: "https://oauth2.googleapis.com/token".into(),
            body: "client_secret=do-not-put-this-in-argv".into(),
            timeout: Duration::from_secs(5),
        };
        let args = curl_args(&request, "5");

        assert!(args.windows(2).any(|pair| pair == ["--data-binary", "@-"]));
        assert!(!args.iter().any(|arg| arg.contains(&request.body)));

        let get = HttpRequest {
            method: "GET".into(),
            body: String::new(),
            ..request
        };
        let get_args = curl_args(&get, "5");
        assert!(!get_args
            .iter()
            .any(|arg| arg == "--data-binary" || arg == "@-"));
    }

    #[test]
    fn curl_output_parsing_is_bounded_and_preserves_status() {
        let response = parse_curl_output(b"{\"error\":\"bad\"}\n401").unwrap();
        assert_eq!(response.status, 401);
        assert_eq!(response.body, "{\"error\":\"bad\"}");
        assert!(parse_curl_output(b"not-a-response").is_none());
        assert!(parse_curl_output(&vec![b'x'; CURL_MAX_RESPONSE_BYTES + 1]).is_none());
    }

    #[test]
    fn peer_retry_delay_is_exponential_and_capped() {
        assert_eq!(retry_delay(1), Duration::from_secs(1));
        assert_eq!(retry_delay(2), Duration::from_secs(2));
        assert_eq!(retry_delay(6), Duration::from_secs(32));
        assert_eq!(retry_delay(30), Duration::from_secs(32));
    }
}
