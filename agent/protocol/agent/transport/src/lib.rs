//! Authenticated Host/Cliente transport over a bundled Tor SOCKS endpoint.
//! Tests use injected loopback runtimes; this crate never starts system Tor.

use localscale_agent_protocol::{
    decode_frame, encode_frame, CryptoError, CryptoKey, HandshakeEnvelope, Message,
    NonceAllocator, ParseError, ReplayGuard, Role, SessionNonce, ValidationError,
    MAX_FRAME_SIZE, VERSION,
};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use fs2::FileExt;
use std::{
    fmt,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    fs::{self, OpenOptions},
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
    sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}},
};

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A crash-safe, caller-owned nonce allocator for persisted CryptoKeys.
/// The counter is written to a temporary file, synced, and atomically renamed
/// before the nonce is returned. The state file contains no key material.
pub struct FileNonceAllocator { path: PathBuf, next: [u8; 24] }

impl FileNonceAllocator {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, TransportError> {
        let path = path.into();
        if let Some(parent) = path.parent() { fs::create_dir_all(parent)?; }
        let next = match fs::read_to_string(&path) {
            Ok(text) => decode_nonce(text.trim()).ok_or(TransportError::Protocol("invalid nonce state"))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let mut value = [0u8; 24]; OsRng.fill_bytes(&mut value); value
            }
            Err(e) => return Err(e.into()),
        };
        Ok(Self { path, next })
    }
    fn persist(&self, value: &[u8; 24]) -> Result<(), TransportError> {
        let tmp = self.path.with_extension(format!(
            "next-{}-{}", std::process::id(), TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
        let mut file = options.open(&tmp)?;
        file.write_all(hex(value).as_bytes())?;
        file.sync_all()?;
        fs::rename(&tmp, &self.path)?;
        #[cfg(unix)] {
            let parent = self.path.parent().unwrap_or_else(|| std::path::Path::new("."));
            OpenOptions::new().read(true).open(parent)?.sync_all()?;
        }
        Ok(())
    }
}
impl NonceAllocator for FileNonceAllocator {
    fn allocate(&mut self) -> Result<[u8; 24], CryptoError> {
        let lock_path = self.path.with_extension("lock");
        let lock = OpenOptions::new().create(true).read(true).write(true).open(lock_path)
            .map_err(|_| CryptoError::NonceReuse)?;
        lock.lock_exclusive().map_err(|_| CryptoError::NonceReuse)?;
        let allocated = match fs::read_to_string(&self.path) {
            Ok(text) => decode_nonce(text.trim()).ok_or(CryptoError::NonceReuse)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let mut value = [0u8; 24]; OsRng.fill_bytes(&mut value); value
            }
            Err(_) => return Err(CryptoError::NonceReuse),
        };
        let mut following = allocated;
        for byte in following.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 { break; }
        }
        if following == [0; 24] { return Err(CryptoError::NonceReuse); }
        self.persist(&following).map_err(|_| CryptoError::NonceReuse)?;
        self.next = following;
        Ok(allocated)
    }
}

/// Deterministically derives the shared transport key from an invitation
/// secret. Both sides must obtain the secret through their existing invitation
/// flow; it is never sent over the Onion connection.
pub fn key_from_invitation_secret(secret: &str) -> CryptoKey {
    let digest = Sha256::digest(secret.as_bytes());
    CryptoKey::from_bytes(&digest).expect("SHA-256 always produces a 32-byte key")
}

fn decode_nonce(text: &str) -> Option<[u8; 24]> {
    if text.len() != 48 { return None; }
    let mut value = [0u8; 24];
    for (i, slot) in value.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(value)
}

pub trait TorRuntime {
    fn socks_endpoint(&self) -> Option<SocketAddr>;
    fn is_ready(&self) -> bool;
}

#[derive(Debug)]
pub enum TransportError {
    Unavailable(&'static str),
    NotReady(&'static str),
    InvalidEndpoint,
    Io(io::Error),
    Timeout,
    Frame,
    Crypto(CryptoError),
    Parse(ParseError),
    Validation(ValidationError),
    Protocol(&'static str),
}
impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for TransportError {}
impl From<io::Error> for TransportError {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::TimedOut {
            Self::Timeout
        } else {
            Self::Io(e)
        }
    }
}
impl From<CryptoError> for TransportError {
    fn from(e: CryptoError) -> Self { Self::Crypto(e) }
}
impl From<ParseError> for TransportError {
    fn from(e: ParseError) -> Self { Self::Parse(e) }
}
impl From<ValidationError> for TransportError {
    fn from(e: ValidationError) -> Self { Self::Validation(e) }
}

pub struct AuthenticatedStream {
    stream: TcpStream,
    peer_node_id: String,
}
impl AuthenticatedStream {
    pub fn peer_node_id(&self) -> &str { &self.peer_node_id }
    pub fn send(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        write_frame(&mut self.stream, payload)
    }
    pub fn receive(&mut self) -> Result<Vec<u8>, TransportError> {
        read_frame(&mut self.stream)
    }
}

/// Host-side transport with an explicit caller-owned nonce allocator.
pub struct HostTransport {
    listener: TcpListener,
    key: CryptoKey,
    node_id: String,
    timeout: Duration,
    replay: ReplayGuard,
    allocator: Box<dyn NonceAllocator + Send>,
    acceptance_gate: Option<Arc<AtomicBool>>,
}
impl HostTransport {
    pub fn bind(
        addr: SocketAddr,
        key: CryptoKey,
        node_id: impl Into<String>,
        allocator: Box<dyn NonceAllocator + Send>,
    ) -> Result<Self, TransportError> {
        Self::bind_with_timeout(addr, key, node_id, DEFAULT_TIMEOUT, allocator)
    }

    pub fn bind_with_timeout(
        addr: SocketAddr,
        key: CryptoKey,
        node_id: impl Into<String>,
        timeout: Duration,
        allocator: Box<dyn NonceAllocator + Send>,
    ) -> Result<Self, TransportError> {
        let node_id = node_id.into();
        if node_id.is_empty() {
            return Err(TransportError::Protocol("host node id is required"));
        }
        Ok(Self {
            listener: TcpListener::bind(addr)?,
            key,
            node_id,
            timeout,
            replay: ReplayGuard::default(),
            allocator,
            acceptance_gate: None,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.listener.local_addr()?)
    }

    pub fn set_acceptance_gate(&mut self, gate: Arc<AtomicBool>) {
        self.acceptance_gate = Some(gate);
    }

    pub fn accept(&mut self) -> Result<AuthenticatedStream, TransportError> {
        let (mut stream, _) = self.listener.accept()?;
        if self.acceptance_gate.as_ref().is_some_and(|gate| !gate.load(Ordering::Acquire)) {
            return Err(TransportError::Protocol("peer transport revoked"));
        }
        set_deadline(&stream, self.timeout)?;
        let envelope_bytes = read_frame(&mut stream)?;
        let envelope = HandshakeEnvelope::from_bytes(&envelope_bytes)?;
        let parsed = envelope
            .open(&self.key, Role::Cliente, "cliente")
            .or_else(|_| find_and_open_client(&envelope, &self.key, &envelope_bytes))?;
        let init = localscale_agent_protocol::parse_message(&parsed)?;
        let (client_id, _timestamp, nonce_text) = match &init {
            Message::HandshakeInit { node_id, timestamp, nonce } => (node_id, *timestamp, nonce),
            _ => return Err(TransportError::Protocol("expected handshake init")),
        };
        let now = unix_now();
        self.replay.accept(&init, now, Role::Host)?;
        let session = session_nonce(&envelope.nonce());
        self.replay.accept_session(
            &session,
            client_id,
            localscale_agent_protocol::PeerRole::Cliente,
        )?;
        let response = Message::HandshakeResponse {
            node_id: self.node_id.clone(),
            timestamp: now,
            nonce: nonce_text.clone(),
        };
        let sealed = HandshakeEnvelope::seal_with_allocator(
            &self.key,
            Role::Host,
            &self.node_id,
            self.allocator.as_mut(),
            &encode_message(&response),
        )?;
        write_frame(&mut stream, sealed.as_bytes())?;
        Ok(AuthenticatedStream { stream, peer_node_id: client_id.clone() })
    }
}

// The envelope authenticates the node id, so inspect its stable header only to obtain it.
fn find_and_open_client(
    envelope: &HandshakeEnvelope,
    key: &CryptoKey,
    bytes: &[u8],
) -> Result<Vec<u8>, TransportError> {
    if bytes.len() < 7 {
        return Err(TransportError::Protocol("malformed client envelope"));
    }
    let n = u16::from_be_bytes([bytes[5], bytes[6]]) as usize;
    if 7 + n > bytes.len() {
        return Err(TransportError::Protocol("malformed client envelope"));
    }
    let id = std::str::from_utf8(&bytes[7..7 + n])
        .map_err(|_| TransportError::Protocol("invalid client node id"))?;
    Ok(envelope.open(key, Role::Cliente, id)?)
}

/// Cliente-side transport with an explicit caller-owned nonce allocator.
pub struct ClienteTransport {
    runtime: Box<dyn TorRuntime>,
    key: CryptoKey,
    node_id: String,
    host_node_id: String,
    timeout: Duration,
    allocator: Box<dyn NonceAllocator + Send>,
}
impl ClienteTransport {
    pub fn new(
        runtime: Box<dyn TorRuntime>,
        key: CryptoKey,
        node_id: impl Into<String>,
        host_node_id: impl Into<String>,
        allocator: Box<dyn NonceAllocator + Send>,
    ) -> Self {
        Self {
            runtime,
            key,
            node_id: node_id.into(),
            host_node_id: host_node_id.into(),
            timeout: DEFAULT_TIMEOUT,
            allocator,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn connect(&mut self, host: &str, port: u16) -> Result<AuthenticatedStream, TransportError> {
        if !self.runtime.is_ready() {
            return Err(TransportError::NotReady("bundled Tor runtime is not ready"));
        }
        let socks = self
            .runtime
            .socks_endpoint()
            .ok_or(TransportError::Unavailable("bundled Tor SOCKS endpoint is unavailable"))?;
        if host.is_empty() || host.bytes().any(|b| b.is_ascii_control() || b == b' ') {
            return Err(TransportError::InvalidEndpoint);
        }
        let mut stream = connect_socks(socks, host, port, self.timeout)?;
        let nonce = fresh_nonce();
        let init = Message::HandshakeInit {
            node_id: self.node_id.clone(),
            timestamp: unix_now(),
            nonce: hex(&nonce),
        };
        let sealed = HandshakeEnvelope::seal_with_allocator(
            &self.key,
            Role::Cliente,
            &self.node_id,
            self.allocator.as_mut(),
            &encode_message(&init),
        )?;
        write_frame(&mut stream, sealed.as_bytes())?;
        let response_bytes = read_frame(&mut stream)?;
        let response_env = HandshakeEnvelope::from_bytes(&response_bytes)?;
        let response = response_env.open(&self.key, Role::Host, &self.host_node_id)?;
        let message = localscale_agent_protocol::parse_message(&response)?;
        let now = unix_now();
        localscale_agent_protocol::validate_message(&message, now, Role::Cliente)?;
        match message {
            Message::HandshakeResponse { node_id, nonce: echoed, .. }
                if node_id == self.host_node_id && echoed == hex(&nonce) =>
            {
                Ok(AuthenticatedStream { stream, peer_node_id: node_id })
            }
            _ => Err(TransportError::Protocol("invalid handshake response")),
        }
    }
}

fn encode_message(message: &Message) -> Vec<u8> {
    match message {
        Message::HandshakeInit { node_id, timestamp, nonce } => {
            format!("v{VERSION}|handshake|init|{node_id}|{timestamp}|{nonce}")
        }
        Message::HandshakeResponse { node_id, timestamp, nonce } => {
            format!("v{VERSION}|handshake|response|{node_id}|{timestamp}|{nonce}")
        }
        Message::Keepalive { node_id, timestamp } => format!("v{VERSION}|keepalive|{node_id}|{timestamp}"),
        Message::MtuProbe { node_id, mtu } => format!("v{VERSION}|mtu|{node_id}|{mtu}"),
    }
    .into_bytes()
}
fn write_frame(stream: &mut TcpStream, payload: &[u8]) -> Result<(), TransportError> {
    let frame = encode_frame(payload).map_err(|_| TransportError::Frame)?;
    stream.write_all(&frame)?;
    stream.flush()?;
    Ok(())
}
fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>, TransportError> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head)?;
    let len = u32::from_be_bytes(head) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(TransportError::Frame);
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body)?;
    let mut frame = head.to_vec();
    frame.extend_from_slice(&body);
    Ok(decode_frame(&frame).map_err(|_| TransportError::Frame)?.to_vec())
}
fn set_deadline(stream: &TcpStream, timeout: Duration) -> Result<(), TransportError> {
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    Ok(())
}
fn connect_socks(
    socks: SocketAddr,
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<TcpStream, TransportError> {
    let mut s = TcpStream::connect_timeout(&socks, timeout)?;
    set_deadline(&s, timeout)?;
    s.write_all(&[5, 1, 0])?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r)?;
    if r != [5, 0] {
        return Err(TransportError::Protocol("SOCKS5 authentication unavailable"));
    }
    let hb = host.as_bytes();
    if hb.len() > 255 {
        return Err(TransportError::InvalidEndpoint);
    }
    s.write_all(&[5, 1, 0, 3, hb.len() as u8])?;
    s.write_all(hb)?;
    s.write_all(&port.to_be_bytes())?;
    let mut h = [0u8; 4];
    s.read_exact(&mut h)?;
    if h[1] != 0 {
        return Err(TransportError::Protocol("SOCKS5 connection rejected"));
    }
    let skip = match h[3] {
        1 => 4,
        3 => {
            let mut n = [0u8; 1];
            s.read_exact(&mut n)?;
            n[0] as usize
        }
        4 => 16,
        _ => return Err(TransportError::Protocol("invalid SOCKS5 address type")),
    };
    let mut tail = vec![0u8; skip + 2];
    s.read_exact(&mut tail)?;
    Ok(s)
}
fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}
fn fresh_nonce() -> [u8; 24] {
    let mut n = [0u8; 24];
    OsRng.fill_bytes(&mut n);
    n
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn session_nonce(n: &[u8; 24]) -> SessionNonce {
    let mut out = [0u8; 32];
    out[..24].copy_from_slice(n);
    SessionNonce::from_bytes(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestNonceAllocator { next: u8 }
    impl NonceAllocator for TestNonceAllocator {
        fn allocate(&mut self) -> Result<[u8; 24], CryptoError> {
            let nonce = [self.next; 24];
            self.next = self.next.wrapping_add(1);
            Ok(nonce)
        }
    }

    struct LoopbackRuntime(SocketAddr, bool);
    impl TorRuntime for LoopbackRuntime {
        fn socks_endpoint(&self) -> Option<SocketAddr> { Some(self.0) }
        fn is_ready(&self) -> bool { self.1 }
    }
    struct SocksProxy { addr: SocketAddr }
    fn proxy(target: SocketAddr) -> SocksProxy {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            let mut m = [0; 3];
            c.read_exact(&mut m).unwrap();
            c.write_all(&[5, 0]).unwrap();
            let mut h = [0; 5];
            c.read_exact(&mut h).unwrap();
            let mut host = vec![0; h[4] as usize];
            c.read_exact(&mut host).unwrap();
            let mut p = [0; 2];
            c.read_exact(&mut p).unwrap();
            let mut t = TcpStream::connect(target).unwrap();
            c.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
            let c_to_t = c.try_clone().unwrap();
            let t_to_c = t.try_clone().unwrap();
            std::thread::spawn(move || {
                io::copy(&mut c_to_t.try_clone().unwrap(), &mut t_to_c.try_clone().unwrap()).unwrap();
            });
            io::copy(&mut t, &mut c).unwrap();
        });
        SocksProxy { addr }
    }

    #[test]
    fn loopback_socks_handshake_interoperates() {
        let key_bytes = CryptoKey::generate().to_bytes();
        let host_key = CryptoKey::from_bytes(&key_bytes).unwrap();
        let client_key = CryptoKey::from_bytes(&key_bytes).unwrap();
        let mut host = HostTransport::bind(
            "127.0.0.1:0".parse().unwrap(),
            host_key,
            "host-1",
            Box::new(TestNonceAllocator { next: 1 }),
        ).unwrap();
        let addr = host.local_addr().unwrap();
        let proxy = proxy(addr);
        let rt = LoopbackRuntime(proxy.addr, true);
        let mut client = ClienteTransport::new(
            Box::new(rt), client_key, "cliente-1", "host-1",
            Box::new(TestNonceAllocator { next: 2 }),
        );
        let j = std::thread::spawn(move || {
            let mut s = host.accept().unwrap();
            assert_eq!(s.peer_node_id(), "cliente-1");
            assert_eq!(s.receive().unwrap(), b"ping");
        });
        let mut c = client.connect("host.onion", 1234).unwrap();
        c.send(b"ping").unwrap();
        j.join().unwrap();
    }

    #[test]
    fn unavailable_and_not_ready_are_explicit() {
        let k = CryptoKey::generate();
        let mut c = ClienteTransport::new(
            Box::new(LoopbackRuntime("127.0.0.1:1".parse().unwrap(), false)),
            k, "c", "h", Box::new(TestNonceAllocator { next: 1 }),
        );
        assert!(matches!(c.connect("h.onion", 1), Err(TransportError::NotReady(_))));
    }

    #[test]
    fn file_nonce_allocator_survives_reload_and_never_persists_key_material() {
        let path = std::env::temp_dir().join(format!("localscale-nonce-{}", std::process::id()));
        let first = {
            let mut allocator = FileNonceAllocator::open(&path).unwrap();
            allocator.allocate().unwrap()
        };
        let second = FileNonceAllocator::open(&path).unwrap().allocate().unwrap();
        assert_ne!(first, second);
        assert_eq!(fs::read_to_string(&path).unwrap().len(), 48);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn file_nonce_allocator_is_unique_across_processes() {
        let path = std::env::var_os("LOCALSCALE_NONCE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join(format!("localscale-nonce-concurrent-{}", std::process::id())));
        if std::env::var_os("LOCALSCALE_NONCE_CHILD").is_some() {
            let mut allocator = FileNonceAllocator::open(&path).unwrap();
            for _ in 0..32 { allocator.allocate().unwrap(); }
            return;
        }
        let _ = fs::remove_file(&path);
        fs::write(&path, "000000000000000000000000000000000000000000000000").unwrap();
        let mut children = Vec::new();
        for _ in 0..8 {
            children.push(std::process::Command::new(std::env::current_exe().unwrap())
                .arg("tests::file_nonce_allocator_is_unique_across_processes")
                .arg("--exact")
                .env("LOCALSCALE_NONCE_CHILD", "1")
                .env("LOCALSCALE_NONCE_PATH", &path)
                .env("RUST_TEST_THREADS", "1")
                .spawn()
                .unwrap());
        }
        assert!(children.into_iter().all(|mut child| child.wait().unwrap().success()));
        let state = decode_nonce(&fs::read_to_string(&path).unwrap()).unwrap();
        let mut expected = [0u8; 24];
        expected[22] = 1;
        assert_eq!(state, expected);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("lock"));
    }

    #[test]
    fn invitation_secret_derives_the_same_opening_key() {
        let a = key_from_invitation_secret("test-invitation-secret");
        let b = key_from_invitation_secret("test-invitation-secret");
        let mut allocator = TestNonceAllocator { next: 9 };
        let envelope = HandshakeEnvelope::seal_with_allocator(&a, Role::Host, "host-1", &mut allocator, b"ok").unwrap();
        assert_eq!(envelope.open(&b, Role::Host, "host-1").unwrap(), b"ok");
        assert!(envelope.open(&key_from_invitation_secret("different"), Role::Host, "host-1").is_err());
    }
}
