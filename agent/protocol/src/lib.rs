//! LocalScale agent wire protocol primitives.
//!
//! The parser is deliberately small and strict: fields are ASCII tokens separated by
//! `|`, and values are validated before being exposed to callers. This is a protocol
//! skeleton, not a secure channel implementation.

use std::collections::HashMap;
use std::fmt;

pub const VERSION: u8 = 1;
pub const REPLAY_WINDOW_SECS: u64 = 300;
pub const MIN_MTU: u16 = 576;
pub const MAX_MTU: u16 = 9_000;
pub const MAX_FRAME_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerRole { Host, Cliente }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError { Incomplete, TooLarge, TrailingBytes, LengthOverflow }
impl fmt::Display for FrameError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{self:?}") } }
impl std::error::Error for FrameError {}

pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    if payload.len() > MAX_FRAME_SIZE { return Err(FrameError::TooLarge); }
    let len = u32::try_from(payload.len()).map_err(|_| FrameError::LengthOverflow)?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

pub fn decode_frame(frame: &[u8]) -> Result<&[u8], FrameError> {
    if frame.len() < 4 { return Err(FrameError::Incomplete); }
    let len = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
    if len > MAX_FRAME_SIZE { return Err(FrameError::TooLarge); }
    let end = 4usize.checked_add(len).ok_or(FrameError::LengthOverflow)?;
    if frame.len() < end { return Err(FrameError::Incomplete); }
    if frame.len() != end { return Err(FrameError::TrailingBytes); }
    Ok(&frame[4..end])
}

fn valid_onion_hostname(value: &str) -> bool {
    let Some(label) = value.strip_suffix(".onion") else { return false; };
    label.len() == 56 && label.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
}

fn valid_invitation_secret(value: &str) -> bool {
    (16..=128).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostInvitation { host_node_id: String, public_endpoint: String, invitation_secret: zeroize::Zeroizing<String> }
impl HostInvitation {
    pub fn new(host_node_id: &str, public_endpoint: &str, invitation_secret: &str) -> Result<Self, ValidationError> {
        if !valid_node_id(host_node_id) { return Err(ValidationError::InvalidNodeId); }
        if !valid_onion_hostname(public_endpoint) || !valid_invitation_secret(invitation_secret) { return Err(ValidationError::InvalidNonce); }
        Ok(Self { host_node_id: host_node_id.into(), public_endpoint: public_endpoint.into(), invitation_secret: zeroize::Zeroizing::new(invitation_secret.into()) })
    }
    pub fn host_node_id(&self) -> &str { &self.host_node_id }
    pub fn public_endpoint(&self) -> &str { &self.public_endpoint }
    pub(crate) fn secret(&self) -> &str { self.invitation_secret.as_str() }
    pub fn diagnostics(&self) -> String { format!("configured host={} endpoint={} transport=unavailable", self.host_node_id, self.public_endpoint) }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientConfig { client_node_id: String, host_node_id: String, public_endpoint: String, invitation_secret: zeroize::Zeroizing<String> }
impl ClientConfig {
    pub fn from_invitation(invitation: &HostInvitation, client_node_id: &str) -> Result<Self, ValidationError> {
        Self::client(client_node_id, invitation.host_node_id(), invitation.public_endpoint(), invitation.secret())
    }
    pub fn client(client_node_id: &str, host_node_id: &str, public_endpoint: &str, invitation_secret: &str) -> Result<Self, ValidationError> {
        if !valid_node_id(client_node_id) || !valid_node_id(host_node_id) { return Err(ValidationError::InvalidNodeId); }
        if !valid_onion_hostname(public_endpoint) || !valid_invitation_secret(invitation_secret) { return Err(ValidationError::InvalidNonce); }
        Ok(Self { client_node_id: client_node_id.into(), host_node_id: host_node_id.into(), public_endpoint: public_endpoint.into(), invitation_secret: zeroize::Zeroizing::new(invitation_secret.into()) })
    }
    pub fn role(&self) -> PeerRole { PeerRole::Cliente }
    pub fn host_node_id(&self) -> &str { &self.host_node_id }
    pub fn public_endpoint(&self) -> &str { &self.public_endpoint }
    pub fn diagnostics(&self) -> String { format!("configured client={} host={} endpoint={} transport=unavailable", self.client_node_id, self.host_node_id, self.public_endpoint) }
}

pub struct PeerConfig;
impl PeerConfig {
    pub fn client(client_node_id: &str, host_node_id: &str, public_endpoint: &str, invitation_secret: &str) -> Result<ClientConfig, ValidationError> {
        ClientConfig::client(client_node_id, host_node_id, public_endpoint, invitation_secret)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionNonce([u8; 32]);
impl SessionNonce { pub fn from_bytes(value: [u8; 32]) -> Self { Self(value) } }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role { Host, Cliente }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    HandshakeInit { node_id: String, timestamp: u64, nonce: String },
    HandshakeResponse { node_id: String, timestamp: u64, nonce: String },
    Keepalive { node_id: String, timestamp: u64 },
    MtuProbe { node_id: String, mtu: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    InvalidUtf8,
    InvalidFieldCount,
    InvalidVersion,
    UnsupportedVersion(u8),
    UnknownMessage,
    InvalidTimestamp,
    InvalidMtu,
    InvalidNodeId,
    InvalidNonce,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{self:?}") }
}
impl std::error::Error for ParseError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    InvalidNodeId,
    InvalidNonce,
    TimestampOutsideReplayWindow,
    ReplayDetected,
    WrongRole,
    InvalidMtu,
}
impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{self:?}") }
}
impl std::error::Error for ValidationError {}

/// Parse the canonical v1 form: `v1|kind|...`.
pub fn parse_message(input: &[u8]) -> Result<Message, ParseError> {
    let text = std::str::from_utf8(input).map_err(|_| ParseError::InvalidUtf8)?;
    let fields: Vec<&str> = text.split('|').collect();
    if fields.len() < 2 { return Err(ParseError::InvalidFieldCount); }
    let version = fields[0].strip_prefix('v').ok_or(ParseError::InvalidVersion)?
        .parse::<u8>().map_err(|_| ParseError::InvalidVersion)?;
    if version != VERSION { return Err(ParseError::UnsupportedVersion(version)); }
    match (fields[1], fields.as_slice()) {
        ("handshake", [_, _, phase, node, timestamp, nonce]) => {
            let msg = match *phase {
                "init" => Message::HandshakeInit { node_id: (*node).into(), timestamp: parse_u64(timestamp)?, nonce: (*nonce).into() },
                "response" => Message::HandshakeResponse { node_id: (*node).into(), timestamp: parse_u64(timestamp)?, nonce: (*nonce).into() },
                _ => return Err(ParseError::UnknownMessage),
            };
            validate_syntax(&msg)?;
            Ok(msg)
        }
        ("keepalive", [_, _, node, timestamp]) => {
            let msg = Message::Keepalive { node_id: (*node).into(), timestamp: parse_u64(timestamp)? };
            validate_syntax(&msg)?; Ok(msg)
        }
        ("mtu", [_, _, node, mtu]) => {
            let mtu = mtu.parse::<u16>().map_err(|_| ParseError::InvalidMtu)?;
            let msg = Message::MtuProbe { node_id: (*node).into(), mtu };
            validate_syntax(&msg)?; Ok(msg)
        }
        _ => Err(ParseError::UnknownMessage),
    }
}

fn parse_u64(value: &str) -> Result<u64, ParseError> { value.parse().map_err(|_| ParseError::InvalidTimestamp) }

fn valid_node_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}
fn valid_nonce(value: &str) -> bool {
    value.len() >= 16 && value.len() <= 128 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
fn validate_syntax(message: &Message) -> Result<(), ParseError> {
    let node = match message { Message::HandshakeInit { node_id, .. } | Message::HandshakeResponse { node_id, .. } | Message::Keepalive { node_id, .. } | Message::MtuProbe { node_id, .. } => node_id };
    if !valid_node_id(node) { return Err(ParseError::InvalidNodeId); }
    match message {
        Message::HandshakeInit { nonce, .. } | Message::HandshakeResponse { nonce, .. } if !valid_nonce(nonce) => Err(ParseError::InvalidNonce),
        Message::MtuProbe { mtu, .. } if *mtu < MIN_MTU || *mtu > MAX_MTU => Err(ParseError::InvalidMtu),
        _ => Ok(()),
    }
}

pub fn validate_message(message: &Message, now: u64, role: Role) -> Result<(), ValidationError> {
    let node = match message { Message::HandshakeInit { node_id, .. } | Message::HandshakeResponse { node_id, .. } | Message::Keepalive { node_id, .. } | Message::MtuProbe { node_id, .. } => node_id };
    if !valid_node_id(node) { return Err(ValidationError::InvalidNodeId); }
    match message {
        Message::HandshakeInit { timestamp, nonce, .. } => {
            if role != Role::Host { return Err(ValidationError::WrongRole); }
            if !valid_nonce(nonce) { return Err(ValidationError::InvalidNonce); }
            check_window(*timestamp, now)
        }
        Message::HandshakeResponse { timestamp, nonce, .. } => {
            if role != Role::Cliente { return Err(ValidationError::WrongRole); }
            if !valid_nonce(nonce) { return Err(ValidationError::InvalidNonce); }
            check_window(*timestamp, now)
        }
        Message::Keepalive { timestamp, .. } => check_window(*timestamp, now),
        Message::MtuProbe { mtu, .. } if *mtu < MIN_MTU || *mtu > MAX_MTU => Err(ValidationError::InvalidMtu),
        Message::MtuProbe { .. } => Ok(()),
    }
}

fn check_window(timestamp: u64, now: u64) -> Result<(), ValidationError> {
    if timestamp.abs_diff(now) > REPLAY_WINDOW_SECS { Err(ValidationError::TimestampOutsideReplayWindow) } else { Ok(()) }
}

/// Stateful replay protection to be owned by the connection/session layer.
#[derive(Debug, Default)]
pub struct ReplayGuard {
    seen: HashMap<String, u64>,
    sessions: HashMap<SessionNonce, (String, PeerRole)>,
}
impl ReplayGuard {
    pub fn accept(&mut self, message: &Message, now: u64, role: Role) -> Result<(), ValidationError> {
        validate_message(message, now, role)?;
        let nonce = match message {
            Message::HandshakeInit { nonce, .. } | Message::HandshakeResponse { nonce, .. } => Some(nonce),
            _ => None,
        };
        self.seen.retain(|_, timestamp| now.saturating_sub(*timestamp) <= REPLAY_WINDOW_SECS);
        if let Some(nonce) = nonce {
            if self.seen.contains_key(nonce) { return Err(ValidationError::ReplayDetected); }
            self.seen.insert(nonce.clone(), now);
        }
        Ok(())
    }

    pub fn accept_session(&mut self, nonce: &SessionNonce, peer_node_id: &str, role: PeerRole) -> Result<(), ValidationError> {
        if !valid_node_id(peer_node_id) { return Err(ValidationError::InvalidNodeId); }
        if let Some((existing_peer, existing_role)) = self.sessions.get(nonce) {
            if existing_peer != peer_node_id || *existing_role != role { return Err(ValidationError::WrongRole); }
            return Err(ValidationError::ReplayDetected);
        }
        self.sessions.insert(*nonce, (peer_node_id.to_string(), role));
        Ok(())
    }
}

use chacha20poly1305::{aead::{Aead, KeyInit}, Key, XChaCha20Poly1305, XNonce};
use rand::{rngs::OsRng, RngCore};
use std::collections::{HashSet, VecDeque};
use std::sync::Mutex;
use zeroize::Zeroizing;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const MAGIC: &[u8; 4] = b"LSV1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    InvalidKeyLength,
    InvalidNodeId,
    AuthenticationFailed,
    NonceReuse,
    UnsafeNoncePolicy,
    MalformedEnvelope,
}
impl fmt::Display for CryptoError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{self:?}") } }
impl std::error::Error for CryptoError {}

/// A 256-bit LocalScale key. The secret is zeroized when this value is dropped.
pub struct CryptoKey {
    secret: Zeroizing<[u8; KEY_LEN]>,
    sealing_allowed: bool,
    used_nonces: Mutex<(HashSet<[u8; NONCE_LEN]>, VecDeque<[u8; NONCE_LEN]>)>,
}
impl CryptoKey {
    pub fn generate() -> Self {
        let mut secret = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut secret);
        Self::from_secret(secret, true)
    }
    /// Load a raw key for opening only. Sealing requires `seal_with_allocator` and a
    /// caller-owned durable allocator, so restart cannot silently reset nonce state.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != KEY_LEN { return Err(CryptoError::InvalidKeyLength); }
        let mut secret = [0u8; KEY_LEN];
        secret.copy_from_slice(bytes);
        Ok(Self::from_secret(secret, false))
    }
    pub fn to_bytes(&self) -> [u8; KEY_LEN] { *self.secret }
    fn from_secret(secret: [u8; KEY_LEN], sealing_allowed: bool) -> Self {
        Self { secret: Zeroizing::new(secret), sealing_allowed, used_nonces: Mutex::new((HashSet::new(), VecDeque::new())) }
    }
    fn record_nonce(&self, nonce: [u8; NONCE_LEN]) -> Result<(), CryptoError> {
        const MAX_TRACKED_NONCES: usize = 4096;
        let mut tracked = self.used_nonces.lock().map_err(|_| CryptoError::NonceReuse)?;
        if !tracked.0.insert(nonce) { return Err(CryptoError::NonceReuse); }
        tracked.1.push_back(nonce);
        if tracked.1.len() > MAX_TRACKED_NONCES {
            if let Some(old) = tracked.1.pop_front() { tracked.0.remove(&old); }
        }
        Ok(())
    }
    fn cipher(&self) -> XChaCha20Poly1305 { XChaCha20Poly1305::new(Key::from_slice(&self.secret[..])) }
}

/// Caller-owned durable nonce allocation. Implementations must persist each
/// allocation atomically before returning it; this trait does not fake storage.
pub trait NonceAllocator {
    fn allocate(&mut self) -> Result<[u8; NONCE_LEN], CryptoError>;
}

/// Authenticated v1 handshake envelope. Its serialized form is stable and self-contained.
pub struct HandshakeEnvelope { bytes: Vec<u8>, nonce: [u8; NONCE_LEN] }
impl HandshakeEnvelope {
    pub fn seal(key: &CryptoKey, role: Role, node_id: &str, plaintext: &[u8]) -> Result<Self, CryptoError> {
        if !key.sealing_allowed { return Err(CryptoError::UnsafeNoncePolicy); }
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        Self::seal_with_nonce_internal(key, role, node_id, nonce, plaintext, true)
    }
    /// Deterministic nonce entry point for interoperability tests only; production
    /// callers must use `seal` or an externally coordinated nonce policy.
    pub fn seal_with_nonce(key: &CryptoKey, role: Role, node_id: &str, nonce: [u8; NONCE_LEN], plaintext: &[u8]) -> Result<Self, CryptoError> {
        Self::seal_with_nonce_internal(key, role, node_id, nonce, plaintext, true)
    }
    pub fn seal_with_allocator<A: NonceAllocator + ?Sized>(key: &CryptoKey, role: Role, node_id: &str, allocator: &mut A, plaintext: &[u8]) -> Result<Self, CryptoError> {
        let nonce = allocator.allocate()?;
        key.record_nonce(nonce)?;
        Self::seal_with_nonce_internal(key, role, node_id, nonce, plaintext, false)
    }
    fn seal_with_nonce_internal(key: &CryptoKey, role: Role, node_id: &str, nonce: [u8; NONCE_LEN], plaintext: &[u8], enforce_policy: bool) -> Result<Self, CryptoError> {
        if enforce_policy && !key.sealing_allowed { return Err(CryptoError::UnsafeNoncePolicy); }
        if !valid_node_id(node_id) { return Err(CryptoError::InvalidNodeId); }
        if !enforce_policy { return Ok(Self::seal_unchecked(key, role, node_id, nonce, plaintext)?); }
        key.record_nonce(nonce)?;
        let ad = associated_data(role, node_id);
        let ciphertext = match key.cipher().encrypt(XNonce::from_slice(&nonce), chacha20poly1305::aead::Payload { msg: plaintext, aad: &ad }) {
            Ok(value) => value,
            Err(_) => return Err(CryptoError::AuthenticationFailed),
        };
        let node = node_id.as_bytes();
        let mut bytes = Vec::with_capacity(4 + 1 + 2 + node.len() + NONCE_LEN + 4 + ciphertext.len());
        bytes.extend_from_slice(MAGIC);
        bytes.push(role_byte(role));
        bytes.extend_from_slice(&(node.len() as u16).to_be_bytes());
        bytes.extend_from_slice(node);
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&ciphertext);
        Ok(Self { bytes, nonce })
    }
    fn seal_unchecked(key: &CryptoKey, role: Role, node_id: &str, nonce: [u8; NONCE_LEN], plaintext: &[u8]) -> Result<Self, CryptoError> {
        let ad = associated_data(role, node_id);
        let ciphertext = key.cipher().encrypt(XNonce::from_slice(&nonce), chacha20poly1305::aead::Payload { msg: plaintext, aad: &ad }).map_err(|_| CryptoError::AuthenticationFailed)?;
        let node = node_id.as_bytes();
        let mut bytes = Vec::with_capacity(4 + 1 + 2 + node.len() + NONCE_LEN + 4 + ciphertext.len());
        bytes.extend_from_slice(MAGIC); bytes.push(role_byte(role));
        bytes.extend_from_slice(&(node.len() as u16).to_be_bytes()); bytes.extend_from_slice(node);
        bytes.extend_from_slice(&nonce); bytes.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes()); bytes.extend_from_slice(&ciphertext);
        Ok(Self { bytes, nonce })
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let parsed = parse_envelope(bytes)?;
        Ok(Self { bytes: bytes.to_vec(), nonce: parsed.nonce })
    }
    pub fn as_bytes(&self) -> &[u8] { &self.bytes }
    pub fn version(&self) -> u8 { VERSION }
    pub fn nonce(&self) -> [u8; NONCE_LEN] { self.nonce }
    pub fn open(&self, key: &CryptoKey, expected_role: Role, expected_node_id: &str) -> Result<Vec<u8>, CryptoError> {
        if !valid_node_id(expected_node_id) { return Err(CryptoError::AuthenticationFailed); }
        let parsed = parse_envelope(&self.bytes)?;
        if parsed.role != expected_role || parsed.node_id != expected_node_id { return Err(CryptoError::AuthenticationFailed); }
        let ad = associated_data(parsed.role, &parsed.node_id);
        key.cipher().decrypt(XNonce::from_slice(&parsed.nonce), chacha20poly1305::aead::Payload { msg: &parsed.ciphertext, aad: &ad }).map_err(|_| CryptoError::AuthenticationFailed)
    }
}

pub struct CryptoProvider;
impl CryptoProvider {
    pub fn generate_key() -> CryptoKey { CryptoKey::generate() }
    pub fn load_key(bytes: &[u8]) -> Result<CryptoKey, CryptoError> { CryptoKey::from_bytes(bytes) }
}

struct ParsedEnvelope { role: Role, node_id: String, nonce: [u8; NONCE_LEN], ciphertext: Vec<u8> }
fn role_byte(role: Role) -> u8 { match role { Role::Host => 0, Role::Cliente => 1 } }
fn associated_data(role: Role, node_id: &str) -> Vec<u8> {
    let mut ad = Vec::with_capacity(2 + 1 + node_id.len());
    ad.extend_from_slice(b"LS");
    ad.push(VERSION);
    ad.push(role_byte(role));
    ad.extend_from_slice(node_id.as_bytes());
    ad
}
fn parse_envelope(bytes: &[u8]) -> Result<ParsedEnvelope, CryptoError> {
    if bytes.len() < 4 + 1 + 2 + NONCE_LEN + 4 || &bytes[..4] != MAGIC { return Err(CryptoError::MalformedEnvelope); }
    let role = match bytes[4] { 0 => Role::Host, 1 => Role::Cliente, _ => return Err(CryptoError::MalformedEnvelope) };
    let node_len = u16::from_be_bytes([bytes[5], bytes[6]]) as usize;
    let node_start: usize = 7;
    let nonce_start = node_start.checked_add(node_len).ok_or(CryptoError::MalformedEnvelope)?;
    let len_start = nonce_start.checked_add(NONCE_LEN).ok_or(CryptoError::MalformedEnvelope)?;
    let end_header = len_start.checked_add(4).ok_or(CryptoError::MalformedEnvelope)?;
    if end_header > bytes.len() { return Err(CryptoError::MalformedEnvelope); }
    let node_id = std::str::from_utf8(&bytes[node_start..nonce_start]).map_err(|_| CryptoError::MalformedEnvelope)?.to_string();
    if !valid_node_id(&node_id) { return Err(CryptoError::MalformedEnvelope); }
    let mut nonce = [0u8; NONCE_LEN]; nonce.copy_from_slice(&bytes[nonce_start..len_start]);
    let ciphertext_len = u32::from_be_bytes(bytes[len_start..end_header].try_into().unwrap()) as usize;
    let end = end_header.checked_add(ciphertext_len).ok_or(CryptoError::MalformedEnvelope)?;
    if ciphertext_len < 16 || end != bytes.len() { return Err(CryptoError::MalformedEnvelope); }
    Ok(ParsedEnvelope { role, node_id, nonce, ciphertext: bytes[end_header..end].to_vec() })
}