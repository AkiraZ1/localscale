//! Authenticated Host/Cliente transport over a bundled Tor SOCKS endpoint.
//! Tests use injected loopback runtimes; this crate never starts system Tor.

use fs2::FileExt;
use localscale_agent_protocol::{
    decode_frame, encode_frame, CryptoError, CryptoKey, HandshakeEnvelope, Message, NonceAllocator,
    ParseError, ReplayGuard, Role, SessionNonce, ValidationError, MAX_FRAME_SIZE, VERSION,
};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

// 10s was tuned against loopback/same-host testing; a real cross-machine Tor
// circuit can legitimately take longer than that under normal guard
// rotation or path-restriction churn (observed directly: "All current
// guards excluded by path restriction type 2" during testing), which was
// enough on its own to blow through 10s and make the heartbeat loop treat a
// healthy-but-slow circuit as dead — tearing down and reconnecting
// indefinitely instead of just waiting a bit longer.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A crash-safe, caller-owned nonce allocator for persisted CryptoKeys.
/// The counter is written to a temporary file, synced, and atomically renamed
/// before the nonce is returned. The state file contains no key material.
pub struct FileNonceAllocator {
    path: PathBuf,
    next: [u8; 24],
}

impl FileNonceAllocator {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, TransportError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let next = match fs::read_to_string(&path) {
            Ok(text) => {
                decode_nonce(text.trim()).ok_or(TransportError::Protocol("invalid nonce state"))?
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let mut value = [0u8; 24];
                OsRng.fill_bytes(&mut value);
                value
            }
            Err(e) => return Err(e.into()),
        };
        Ok(Self { path, next })
    }
    fn persist(&self, value: &[u8; 24]) -> Result<(), TransportError> {
        let tmp = self.path.with_extension(format!(
            "next-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(hex(value).as_bytes())?;
        file.sync_all()?;
        fs::rename(&tmp, &self.path)?;
        #[cfg(unix)]
        {
            let parent = self
                .path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."));
            OpenOptions::new().read(true).open(parent)?.sync_all()?;
        }
        Ok(())
    }
}
impl NonceAllocator for FileNonceAllocator {
    fn allocate(&mut self) -> Result<[u8; 24], CryptoError> {
        let lock_path = self.path.with_extension("lock");
        let lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(lock_path)
            .map_err(|_| CryptoError::NonceReuse)?;
        lock.lock_exclusive().map_err(|_| CryptoError::NonceReuse)?;
        let allocated = match fs::read_to_string(&self.path) {
            Ok(text) => decode_nonce(text.trim()).ok_or(CryptoError::NonceReuse)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let mut value = [0u8; 24];
                OsRng.fill_bytes(&mut value);
                value
            }
            Err(_) => return Err(CryptoError::NonceReuse),
        };
        let mut following = allocated;
        for byte in following.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        if following == [0; 24] {
            return Err(CryptoError::NonceReuse);
        }
        self.persist(&following)
            .map_err(|_| CryptoError::NonceReuse)?;
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

/// One-way, versioned representation persisted by the local peer store. It
/// contains the derived transport key, never the bearer invitation secret.
pub fn stored_transport_key_from_invitation_secret(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    let mut encoded = String::with_capacity(71);
    encoded.push_str("key-v1-");
    for byte in digest {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}

pub fn key_from_stored_transport_key(value: &str) -> Result<CryptoKey, CryptoError> {
    let hex = value
        .strip_prefix("key-v1-")
        .ok_or(CryptoError::InvalidKeyLength)?;
    if hex.len() != 64 {
        return Err(CryptoError::InvalidKeyLength);
    }
    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .map_err(|_| CryptoError::InvalidKeyLength)?;
    }
    CryptoKey::from_bytes(&bytes)
}

fn decode_nonce(text: &str) -> Option<[u8; 24]> {
    if text.len() != 48 {
        return None;
    }
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
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}
impl From<ParseError> for TransportError {
    fn from(e: ParseError) -> Self {
        Self::Parse(e)
    }
}
impl From<ValidationError> for TransportError {
    fn from(e: ValidationError) -> Self {
        Self::Validation(e)
    }
}

pub struct AuthenticatedStream {
    stream: TcpStream,
    peer_node_id: String,
    // Which pending-invitation candidate (see `HostKeyResolver`) actually
    // matched this handshake, if the resolver offered more than one and
    // tagged them — `None` for a plain single-key transport, or a
    // multi-peer host whose connecting client had already been bound to a
    // specific key on some earlier handshake (so there was only the one
    // exact-match candidate to try, carrying no separate tag).
    matched_key_tag: Option<String>,
}
impl AuthenticatedStream {
    pub fn peer_node_id(&self) -> &str {
        &self.peer_node_id
    }

    /// The identifier of the pending invitation this handshake's key
    /// belonged to, if the caller's `HostKeyResolver` tagged it as such —
    /// the caller uses this once, right after a successful `accept()`, to
    /// permanently bind that invitation's registry entry to
    /// `peer_node_id()` so future reconnects from the same device look it
    /// up directly instead of trying every still-pending candidate again.
    pub fn matched_key_tag(&self) -> Option<&str> {
        self.matched_key_tag.as_deref()
    }
    /// Checks whether the authenticated TCP session is still open without consuming
    /// protocol bytes. A pending frame also counts as a live connection.
    pub fn is_connected(&self) -> Result<bool, TransportError> {
        self.stream.set_nonblocking(true)?;
        let result = match self.stream.peek(&mut [0u8; 1]) {
            Ok(0) => Ok(false),
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(true),
            Err(error) => Err(TransportError::Io(error)),
        };
        self.stream.set_nonblocking(false)?;
        result
    }
    pub fn send(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        write_frame(&mut self.stream, payload)
    }
    pub fn receive(&mut self) -> Result<Vec<u8>, TransportError> {
        read_frame(&mut self.stream)
    }

    /// Sends a versioned liveness probe. The monotonically increasing sequence
    /// number lets the caller reject delayed or replayed acknowledgements.
    /// `virtual_ip` is this side's own configured overlay address (empty if
    /// unset) — piggybacked on the heartbeat that already proves liveness,
    /// so the peer can learn it in real time instead of it only ever being
    /// known locally and guessed (or left blank) on the other side.
    pub fn send_ping(
        &mut self,
        node_id: &str,
        sequence: u64,
        virtual_ip: &str,
    ) -> Result<(), TransportError> {
        self.send(heartbeat_frame("ping", node_id, unix_now(), sequence, virtual_ip).as_bytes())
    }

    /// Receives a liveness probe and returns its sequence number and the
    /// sender's advertised virtual IP (empty if it has none configured)
    /// after checking the protocol version, message kind, and authenticated
    /// peer identity.
    pub fn receive_ping(&mut self) -> Result<(u64, String), TransportError> {
        let payload = self.receive()?;
        parse_heartbeat(&payload, "ping", &self.peer_node_id)
    }

    pub fn send_pong(
        &mut self,
        node_id: &str,
        sequence: u64,
        virtual_ip: &str,
    ) -> Result<(), TransportError> {
        self.send(heartbeat_frame("pong", node_id, unix_now(), sequence, virtual_ip).as_bytes())
    }

    /// Receives an acknowledgement for `expected_sequence` and returns the
    /// peer's advertised virtual IP. A connection is considered live only
    /// after this validation succeeds.
    pub fn receive_pong(&mut self, expected_sequence: u64) -> Result<String, TransportError> {
        let payload = self.receive()?;
        let (sequence, virtual_ip) = parse_heartbeat(&payload, "pong", &self.peer_node_id)?;
        if sequence != expected_sequence {
            return Err(TransportError::Protocol("unexpected pong sequence"));
        }
        Ok(virtual_ip)
    }
}

fn heartbeat_frame(
    kind: &str,
    node_id: &str,
    timestamp: u64,
    sequence: u64,
    virtual_ip: &str,
) -> String {
    format!("v{VERSION}|{kind}|{node_id}|{timestamp}|{sequence}|{virtual_ip}")
}

/// Frame-kind discriminator prefixed to every frame once a connection is
/// running in multiplexed mode (see `AuthenticatedStream::into_multiplexed`).
/// A plain (non-multiplexed) connection never writes this byte — it's only
/// meaningful to the demultiplexing reader thread spawned by
/// `into_multiplexed`, which is why it lives as a private implementation
/// detail here rather than a public wire-format constant.
const FRAME_KIND_HEARTBEAT: u8 = 1;
const FRAME_KIND_PACKET: u8 = 2;

/// One side of a connection that has been split into a heartbeat channel and
/// a raw-packet channel sharing the same underlying authenticated stream —
/// the foundation for tunneling arbitrary IP traffic (a virtual network
/// interface) over the same connection that already proves liveness,
/// instead of needing a second connection per peer. A background thread
/// demultiplexes inbound frames by their leading kind byte; writes from
/// either channel are serialized through a shared, mutex-guarded clone of
/// the socket.
pub struct HeartbeatChannel {
    writer: Arc<std::sync::Mutex<TcpStream>>,
    peer_node_id: String,
    inbox: std::sync::mpsc::Receiver<Vec<u8>>,
}

impl HeartbeatChannel {
    pub fn peer_node_id(&self) -> &str {
        &self.peer_node_id
    }

    pub fn send_ping(
        &self,
        node_id: &str,
        sequence: u64,
        virtual_ip: &str,
    ) -> Result<(), TransportError> {
        write_multiplexed(
            &self.writer,
            FRAME_KIND_HEARTBEAT,
            heartbeat_frame("ping", node_id, unix_now(), sequence, virtual_ip).as_bytes(),
        )
    }

    pub fn send_pong(
        &self,
        node_id: &str,
        sequence: u64,
        virtual_ip: &str,
    ) -> Result<(), TransportError> {
        write_multiplexed(
            &self.writer,
            FRAME_KIND_HEARTBEAT,
            heartbeat_frame("pong", node_id, unix_now(), sequence, virtual_ip).as_bytes(),
        )
    }

    pub fn receive_ping(&self, timeout: Duration) -> Result<(u64, String), TransportError> {
        let payload = self
            .inbox
            .recv_timeout(timeout)
            .map_err(|_| TransportError::Timeout)?;
        parse_heartbeat(&payload, "ping", &self.peer_node_id)
    }

    pub fn receive_pong(
        &self,
        expected_sequence: u64,
        timeout: Duration,
    ) -> Result<String, TransportError> {
        let payload = self
            .inbox
            .recv_timeout(timeout)
            .map_err(|_| TransportError::Timeout)?;
        let (sequence, virtual_ip) = parse_heartbeat(&payload, "pong", &self.peer_node_id)?;
        if sequence != expected_sequence {
            return Err(TransportError::Protocol("unexpected pong sequence"));
        }
        Ok(virtual_ip)
    }
}

/// The raw-packet side of a multiplexed connection — this is what a future
/// TUN device reader/writer thread uses: whatever bytes go in on one side's
/// `send_packet` come out of the other side's `receive_packet` (or
/// `try_receive_packet` for a non-blocking poll), with no interpretation of
/// their contents (an IP packet, in the intended use, but this layer does
/// not care).
pub struct PacketChannel {
    writer: Arc<std::sync::Mutex<TcpStream>>,
    inbox: std::sync::mpsc::Receiver<Vec<u8>>,
}

impl PacketChannel {
    pub fn send_packet(&self, packet: &[u8]) -> Result<(), TransportError> {
        write_multiplexed(&self.writer, FRAME_KIND_PACKET, packet)
    }

    pub fn receive_packet(&self, timeout: Duration) -> Result<Vec<u8>, TransportError> {
        self.inbox
            .recv_timeout(timeout)
            .map_err(|_| TransportError::Timeout)
    }

    pub fn try_receive_packet(&self) -> Option<Vec<u8>> {
        self.inbox.try_recv().ok()
    }

    /// A cheap, independently-owned handle for the send side only — since
    /// `receive_packet` needs `&self` on the one `PacketChannel` that owns
    /// the inbound `mpsc::Receiver` (which has a single consumer), a bridge
    /// with one thread reading the peer and one thread reading a local
    /// device needs the write half split out like this rather than trying
    /// to share one `PacketChannel` across both threads.
    pub fn sender(&self) -> PacketSender {
        PacketSender {
            writer: self.writer.clone(),
        }
    }
}

/// The send-only half of a `PacketChannel`, freely cloneable/shareable
/// across threads (see `PacketChannel::sender`).
#[derive(Clone)]
pub struct PacketSender {
    writer: Arc<std::sync::Mutex<TcpStream>>,
}

impl PacketSender {
    pub fn send_packet(&self, packet: &[u8]) -> Result<(), TransportError> {
        write_multiplexed(&self.writer, FRAME_KIND_PACKET, packet)
    }
}

fn write_multiplexed(
    writer: &Arc<std::sync::Mutex<TcpStream>>,
    kind: u8,
    payload: &[u8],
) -> Result<(), TransportError> {
    let mut framed = Vec::with_capacity(payload.len() + 1);
    framed.push(kind);
    framed.extend_from_slice(payload);
    let mut guard = writer.lock().map_err(|_| TransportError::Protocol("writer poisoned"))?;
    write_frame(&mut guard, &framed)
}

impl AuthenticatedStream {
    /// Splits this connection into a `HeartbeatChannel` and a `PacketChannel`
    /// that can be driven concurrently from separate threads, sharing the
    /// same underlying socket. Spawns one background thread that reads
    /// frames off the wire and routes each to the channel matching its
    /// leading kind byte — the only place that byte is ever interpreted.
    pub fn into_multiplexed(self) -> (HeartbeatChannel, PacketChannel) {
        let AuthenticatedStream {
            stream,
            peer_node_id,
            matched_key_tag: _,
        } = self;
        let writer_handle = stream
            .try_clone()
            .expect("cloning a connected TcpStream handle does not fail in practice");
        let writer = Arc::new(std::sync::Mutex::new(writer_handle));
        let (heartbeat_tx, heartbeat_rx) = std::sync::mpsc::channel();
        let (packet_tx, packet_rx) = std::sync::mpsc::channel();
        let mut reader = stream;
        std::thread::spawn(move || loop {
            let framed = match read_frame(&mut reader) {
                Ok(framed) => framed,
                Err(_) => break,
            };
            if framed.is_empty() {
                continue;
            }
            let (kind, payload) = (framed[0], framed[1..].to_vec());
            let delivered = match kind {
                FRAME_KIND_HEARTBEAT => heartbeat_tx.send(payload).is_ok(),
                FRAME_KIND_PACKET => packet_tx.send(payload).is_ok(),
                // An unrecognized kind byte is dropped rather than treated as
                // a fatal error: a future frame kind added by a newer peer
                // must not be able to kill an older peer's connection.
                _ => true,
            };
            if !delivered {
                break;
            }
        });
        (
            HeartbeatChannel {
                writer: writer.clone(),
                peer_node_id,
                inbox: heartbeat_rx,
            },
            PacketChannel {
                writer,
                inbox: packet_rx,
            },
        )
    }
}

fn parse_heartbeat(
    payload: &[u8],
    expected_kind: &str,
    expected_node_id: &str,
) -> Result<(u64, String), TransportError> {
    let text = std::str::from_utf8(payload)
        .map_err(|_| TransportError::Protocol("invalid heartbeat encoding"))?;
    let mut fields = text.split('|');
    let version = fields.next();
    let kind = fields.next();
    let node_id = fields.next();
    let timestamp = fields.next().and_then(|value| value.parse::<u64>().ok());
    let sequence = fields.next().and_then(|value| value.parse::<u64>().ok());
    let virtual_ip = fields.next();
    let expected_version = format!("v{VERSION}");
    if fields.next().is_some()
        || version != Some(expected_version.as_str())
        || kind != Some(expected_kind)
        || node_id != Some(expected_node_id)
        || timestamp.is_none()
        || sequence.is_none()
        || virtual_ip.is_none()
    {
        return Err(TransportError::Protocol("invalid heartbeat"));
    }
    let timestamp = timestamp.expect("checked above");
    if unix_now().abs_diff(timestamp) > 30 {
        return Err(TransportError::Protocol("stale heartbeat"));
    }
    Ok((
        sequence.expect("checked above"),
        virtual_ip.expect("checked above").to_string(),
    ))
}

/// Host-side transport with an explicit caller-owned nonce allocator.
/// Supplies candidate decryption keys for an incoming handshake, given the
/// (not-yet-authenticated) client node id peeked from the envelope header.
/// Exists so a single `HostTransport` can accept connections from more than
/// one paired Cliente, each with its own one-time invitation secret, without
/// weakening that per-device secret into one shared "network password":
/// every candidate is tried in turn against the *same* envelope via
/// [`HandshakeEnvelope::open`] (a pure, side-effect-free check — wrong keys
/// just fail the AEAD tag, exactly like a wrong password), and only one
/// (the one that was actually issued to whoever is really connecting) can
/// ever succeed.
///
/// A single-key `HostTransport` (the original, still-supported shape) is
/// just the degenerate case of one candidate that never changes, which is
/// why `CryptoKey` itself implements this trait below.
pub trait HostKeyResolver: Send {
    /// Returns candidate keys to try, each tagged with an identifier the
    /// caller can use to learn afterward *which* candidate matched (e.g. a
    /// pending invitation's id) — `AuthenticatedStream::matched_key_tag()`
    /// surfaces whichever tag's key actually opened the envelope.
    fn candidates(&self, claimed_node_id: &str) -> Vec<(String, CryptoKey)>;
}

impl HostKeyResolver for CryptoKey {
    fn candidates(&self, _claimed_node_id: &str) -> Vec<(String, CryptoKey)> {
        vec![(String::new(), self.clone_for_resolver())]
    }
}

pub struct HostTransport {
    listener: TcpListener,
    resolver: Box<dyn HostKeyResolver>,
    node_id: String,
    timeout: Duration,
    replay: ReplayGuard,
    allocator: Box<dyn NonceAllocator + Send>,
    acceptance_gate: Option<Arc<AtomicBool>>,
}
impl HostTransport {
    pub fn bind(
        addr: SocketAddr,
        resolver: impl HostKeyResolver + 'static,
        node_id: impl Into<String>,
        allocator: Box<dyn NonceAllocator + Send>,
    ) -> Result<Self, TransportError> {
        Self::bind_with_timeout(addr, resolver, node_id, DEFAULT_TIMEOUT, allocator)
    }

    pub fn bind_with_timeout(
        addr: SocketAddr,
        resolver: impl HostKeyResolver + 'static,
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
            resolver: Box::new(resolver),
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
        if self
            .acceptance_gate
            .as_ref()
            .is_some_and(|gate| !gate.load(Ordering::Acquire))
        {
            return Err(TransportError::Protocol("peer transport revoked"));
        }
        set_deadline(&stream, self.timeout)?;
        let envelope_bytes = read_frame(&mut stream)?;
        let envelope = HandshakeEnvelope::from_bytes(&envelope_bytes)?;
        let claimed_id = peek_client_id(&envelope_bytes)?;
        let (parsed, matched_key, matched_tag) =
            open_with_candidates(&envelope, self.resolver.candidates(claimed_id), claimed_id)?;
        let init = localscale_agent_protocol::parse_message(&parsed)?;
        let (client_id, _timestamp, nonce_text) = match &init {
            Message::HandshakeInit {
                node_id,
                timestamp,
                nonce,
            } => (node_id, *timestamp, nonce),
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
            &matched_key,
            Role::Host,
            &self.node_id,
            self.allocator.as_mut(),
            &encode_message(&response),
        )?;
        write_frame(&mut stream, sealed.as_bytes())?;
        Ok(AuthenticatedStream {
            stream,
            peer_node_id: client_id.clone(),
            matched_key_tag: matched_tag,
        })
    }
}

/// The envelope authenticates the node id, so peeking its stable header
/// (before any decryption) only reveals what the connecting client is
/// *claiming* — resolving which key (if any) actually vouches for that
/// claim happens afterward in `open_with_candidates`.
fn peek_client_id(bytes: &[u8]) -> Result<&str, TransportError> {
    if bytes.len() < 7 {
        return Err(TransportError::Protocol("malformed client envelope"));
    }
    let n = u16::from_be_bytes([bytes[5], bytes[6]]) as usize;
    if 7 + n > bytes.len() {
        return Err(TransportError::Protocol("malformed client envelope"));
    }
    std::str::from_utf8(&bytes[7..7 + n])
        .map_err(|_| TransportError::Protocol("invalid client node id"))
}

/// Tries every candidate key in order, returning the first one whose AEAD
/// tag actually verifies (never any partial/oracle information for the
/// ones that don't — `open` either fully succeeds or fails uniformly).
fn open_with_candidates(
    envelope: &HandshakeEnvelope,
    candidates: Vec<(String, CryptoKey)>,
    claimed_id: &str,
) -> Result<(Vec<u8>, CryptoKey, Option<String>), TransportError> {
    for (tag, key) in candidates {
        if let Ok(plaintext) = envelope.open(&key, Role::Cliente, claimed_id) {
            let tag = if tag.is_empty() { None } else { Some(tag) };
            return Ok((plaintext, key, tag));
        }
    }
    Err(TransportError::Crypto(CryptoError::AuthenticationFailed))
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

    pub fn connect(
        &mut self,
        host: &str,
        port: u16,
    ) -> Result<AuthenticatedStream, TransportError> {
        if !self.runtime.is_ready() {
            return Err(TransportError::NotReady("bundled Tor runtime is not ready"));
        }
        let socks = self
            .runtime
            .socks_endpoint()
            .ok_or(TransportError::Unavailable(
                "bundled Tor SOCKS endpoint is unavailable",
            ))?;
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
            Message::HandshakeResponse {
                node_id,
                nonce: echoed,
                ..
            } if node_id == self.host_node_id && echoed == hex(&nonce) => Ok(AuthenticatedStream {
                stream,
                peer_node_id: node_id,
                matched_key_tag: None,
            }),
            _ => Err(TransportError::Protocol("invalid handshake response")),
        }
    }
}

fn encode_message(message: &Message) -> Vec<u8> {
    match message {
        Message::HandshakeInit {
            node_id,
            timestamp,
            nonce,
        } => {
            format!("v{VERSION}|handshake|init|{node_id}|{timestamp}|{nonce}")
        }
        Message::HandshakeResponse {
            node_id,
            timestamp,
            nonce,
        } => {
            format!("v{VERSION}|handshake|response|{node_id}|{timestamp}|{nonce}")
        }
        Message::Keepalive { node_id, timestamp } => {
            format!("v{VERSION}|keepalive|{node_id}|{timestamp}")
        }
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
    Ok(decode_frame(&frame)
        .map_err(|_| TransportError::Frame)?
        .to_vec())
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
        return Err(TransportError::Protocol(
            "SOCKS5 authentication unavailable",
        ));
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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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

    struct TestNonceAllocator {
        next: u8,
    }
    impl NonceAllocator for TestNonceAllocator {
        fn allocate(&mut self) -> Result<[u8; 24], CryptoError> {
            let nonce = [self.next; 24];
            self.next = self.next.wrapping_add(1);
            Ok(nonce)
        }
    }

    struct LoopbackRuntime(SocketAddr, bool);
    impl TorRuntime for LoopbackRuntime {
        fn socks_endpoint(&self) -> Option<SocketAddr> {
            Some(self.0)
        }
        fn is_ready(&self) -> bool {
            self.1
        }
    }
    struct SocksProxy {
        addr: SocketAddr,
    }
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
                io::copy(
                    &mut c_to_t.try_clone().unwrap(),
                    &mut t_to_c.try_clone().unwrap(),
                )
                .unwrap();
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
        )
        .unwrap();
        let addr = host.local_addr().unwrap();
        let proxy = proxy(addr);
        let rt = LoopbackRuntime(proxy.addr, true);
        let mut client = ClienteTransport::new(
            Box::new(rt),
            client_key,
            "cliente-1",
            "host-1",
            Box::new(TestNonceAllocator { next: 2 }),
        );
        let j = std::thread::spawn(move || {
            let mut s = host.accept().unwrap();
            assert_eq!(s.peer_node_id(), "cliente-1");
            let (sequence, peer_virtual_ip) = s.receive_ping().unwrap();
            assert_eq!(sequence, 7);
            assert_eq!(peer_virtual_ip, "10.0.0.5");
            s.send_pong("host-1", sequence, "10.0.0.6").unwrap();
        });
        let mut c = client.connect("host.onion", 1234).unwrap();
        c.send_ping("cliente-1", 7, "10.0.0.5").unwrap();
        assert_eq!(c.receive_pong(7).unwrap(), "10.0.0.6");
        j.join().unwrap();
    }

    #[test]
    fn multiplexed_heartbeat_and_packets_do_not_interfere() {
        // Foundation for tunneling arbitrary IP traffic (a virtual network
        // interface) over the same connection that already proves
        // liveness: a heartbeat exchange and raw "packet" frames (standing
        // in for what a TUN device would produce) must both arrive intact
        // and in order on their own channel, even when interleaved on the
        // wire, and neither must be mistaken for the other.
        let key_bytes = CryptoKey::generate().to_bytes();
        let host_key = CryptoKey::from_bytes(&key_bytes).unwrap();
        let client_key = CryptoKey::from_bytes(&key_bytes).unwrap();
        let mut host = HostTransport::bind(
            "127.0.0.1:0".parse().unwrap(),
            host_key,
            "host-1",
            Box::new(TestNonceAllocator { next: 1 }),
        )
        .unwrap();
        let addr = host.local_addr().unwrap();
        let proxy = proxy(addr);
        let rt = LoopbackRuntime(proxy.addr, true);
        let mut client = ClienteTransport::new(
            Box::new(rt),
            client_key,
            "cliente-1",
            "host-1",
            Box::new(TestNonceAllocator { next: 2 }),
        );
        let j = std::thread::spawn(move || {
            let s = host.accept().unwrap();
            let (heartbeat, packets) = s.into_multiplexed();
            // A "packet" arrives before the ping does; it must not corrupt
            // or get consumed by the heartbeat channel.
            let received = packets.receive_packet(Duration::from_secs(5)).unwrap();
            assert_eq!(received, b"fake-ip-packet-1");
            let (sequence, peer_virtual_ip) = heartbeat
                .receive_ping(Duration::from_secs(5))
                .unwrap();
            assert_eq!(sequence, 1);
            assert_eq!(peer_virtual_ip, "10.0.0.5");
            heartbeat.send_pong("host-1", sequence, "10.0.0.6").unwrap();
            packets.send_packet(b"fake-ip-packet-2").unwrap();
        });
        let c = client.connect("host.onion", 1234).unwrap();
        let (heartbeat, packets) = c.into_multiplexed();
        packets.send_packet(b"fake-ip-packet-1").unwrap();
        heartbeat.send_ping("cliente-1", 1, "10.0.0.5").unwrap();
        assert_eq!(
            heartbeat.receive_pong(1, Duration::from_secs(5)).unwrap(),
            "10.0.0.6"
        );
        assert_eq!(
            packets.receive_packet(Duration::from_secs(5)).unwrap(),
            b"fake-ip-packet-2"
        );
        j.join().unwrap();
    }

    #[test]
    fn heartbeat_rejects_wrong_kind_identity_and_sequence() {
        let now = unix_now();
        assert_eq!(
            parse_heartbeat(
                format!("v{VERSION}|ping|client-1|{now}|9|10.0.0.5").as_bytes(),
                "ping",
                "client-1"
            )
            .unwrap(),
            (9, "10.0.0.5".to_string())
        );
        assert!(parse_heartbeat(
            format!("v{VERSION}|pong|client-1|{now}|9|10.0.0.5").as_bytes(),
            "ping",
            "client-1"
        )
        .is_err());
        assert!(parse_heartbeat(
            format!("v{VERSION}|ping|other|{now}|9|10.0.0.5").as_bytes(),
            "ping",
            "client-1"
        )
        .is_err());
        // Missing virtual_ip field entirely (old wire format) must also be
        // rejected rather than silently accepted with a default.
        assert!(parse_heartbeat(
            format!("v{VERSION}|ping|client-1|{now}|9").as_bytes(),
            "ping",
            "client-1"
        )
        .is_err());
    }

    #[test]
    fn unavailable_and_not_ready_are_explicit() {
        let k = CryptoKey::generate();
        let mut c = ClienteTransport::new(
            Box::new(LoopbackRuntime("127.0.0.1:1".parse().unwrap(), false)),
            k,
            "c",
            "h",
            Box::new(TestNonceAllocator { next: 1 }),
        );
        assert!(matches!(
            c.connect("h.onion", 1),
            Err(TransportError::NotReady(_))
        ));
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
            .unwrap_or_else(|| {
                std::env::temp_dir().join(format!(
                    "localscale-nonce-concurrent-{}",
                    std::process::id()
                ))
            });
        if std::env::var_os("LOCALSCALE_NONCE_CHILD").is_some() {
            let mut allocator = FileNonceAllocator::open(&path).unwrap();
            for _ in 0..32 {
                allocator.allocate().unwrap();
            }
            return;
        }
        let _ = fs::remove_file(&path);
        fs::write(&path, "000000000000000000000000000000000000000000000000").unwrap();
        let mut children = Vec::new();
        for _ in 0..8 {
            children.push(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .arg("tests::file_nonce_allocator_is_unique_across_processes")
                    .arg("--exact")
                    .env("LOCALSCALE_NONCE_CHILD", "1")
                    .env("LOCALSCALE_NONCE_PATH", &path)
                    .env("RUST_TEST_THREADS", "1")
                    .spawn()
                    .unwrap(),
            );
        }
        assert!(children
            .into_iter()
            .all(|mut child| child.wait().unwrap().success()));
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
        let envelope =
            HandshakeEnvelope::seal_with_allocator(&a, Role::Host, "host-1", &mut allocator, b"ok")
                .unwrap();
        assert_eq!(envelope.open(&b, Role::Host, "host-1").unwrap(), b"ok");
        assert!(envelope
            .open(
                &key_from_invitation_secret("different"),
                Role::Host,
                "host-1"
            )
            .is_err());
    }
}
