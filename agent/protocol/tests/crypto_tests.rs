use localscale_agent_protocol::{CryptoError, CryptoKey, HandshakeEnvelope, NonceAllocator, Role, VERSION};

fn key() -> CryptoKey {
    CryptoKey::generate()
}

#[test]
fn generated_key_round_trips_an_authenticated_handshake() {
    let key = CryptoKey::generate();
    let envelope = HandshakeEnvelope::seal(&key, Role::Host, "host-1", b"hello").unwrap();
    let opened = envelope.open(&key, Role::Host, "host-1").unwrap();
    assert_eq!(opened, b"hello");
    assert_eq!(envelope.version(), VERSION);
    assert_eq!(envelope.nonce().len(), 24);
}

#[test]
fn loading_requires_exact_key_length() {
    assert!(matches!(CryptoKey::from_bytes(&[0u8; 31]), Err(CryptoError::InvalidKeyLength)));
    assert!(matches!(CryptoKey::from_bytes(&[0u8; 33]), Err(CryptoError::InvalidKeyLength)));
}

#[test]
fn tampering_is_an_authentication_failure() {
    let key = key();
    let envelope = HandshakeEnvelope::seal(&key, Role::Host, "host-1", b"hello").unwrap();
    let mut bytes = envelope.as_bytes().to_vec();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    let envelope = HandshakeEnvelope::from_bytes(&bytes).unwrap();
    assert!(matches!(envelope.open(&key, Role::Host, "host-1"), Err(CryptoError::AuthenticationFailed)));
}

#[test]
fn wrong_role_and_node_are_authentication_failures() {
    let key = key();
    let envelope = HandshakeEnvelope::seal(&key, Role::Host, "host-1", b"hello").unwrap();
    assert!(matches!(envelope.open(&key, Role::Cliente, "host-1"), Err(CryptoError::AuthenticationFailed)));
    assert!(matches!(envelope.open(&key, Role::Host, "other"), Err(CryptoError::AuthenticationFailed)));
}

#[test]
fn nonce_reuse_is_rejected() {
    let key = CryptoKey::generate();
    let nonce = [3u8; 24];
    HandshakeEnvelope::seal_with_nonce(&key, Role::Host, "host-1", nonce, b"one").unwrap();
    assert!(matches!(HandshakeEnvelope::seal_with_nonce(&key, Role::Host, "host-1", nonce, b"two"), Err(CryptoError::NonceReuse)));
}

#[test]
fn nonce_reuse_remains_rejected_after_more_than_4096_seals() {
    let key = CryptoKey::generate();
    let first_nonce = [0u8; 24];

    HandshakeEnvelope::seal_with_nonce(&key, Role::Host, "host-1", first_nonce, b"first").unwrap();
    for counter in 1u64..=4096 {
        let mut nonce = [0u8; 24];
        nonce[..8].copy_from_slice(&counter.to_be_bytes());
        HandshakeEnvelope::seal_with_nonce(&key, Role::Host, "host-1", nonce, b"payload").unwrap();
    }

    assert!(matches!(
        HandshakeEnvelope::seal_with_nonce(&key, Role::Host, "host-1", first_nonce, b"replayed"),
        Err(CryptoError::NonceReuse)
    ));
}

#[test]
fn raw_key_reload_rejects_unsafe_sealing_after_restart() {
    let bytes = [7u8; 32];
    let nonce = [4u8; 24];
    let first = CryptoKey::from_bytes(&bytes).unwrap();
    assert!(HandshakeEnvelope::seal_with_nonce(&first, Role::Host, "host-1", nonce, b"one").is_err());
    let reloaded = CryptoKey::from_bytes(&bytes).unwrap();
    assert!(matches!(HandshakeEnvelope::seal(&reloaded, Role::Host, "host-1", b"two"), Err(CryptoError::UnsafeNoncePolicy)));
}

struct DurableAllocator { next: u8 }
impl NonceAllocator for DurableAllocator {
    fn allocate(&mut self) -> Result<[u8; 24], CryptoError> {
        let nonce = [self.next; 24];
        self.next = self.next.checked_add(1).ok_or(CryptoError::NonceReuse)?;
        Ok(nonce)
    }
}

#[test]
fn caller_owned_durable_allocator_allows_raw_key_roundtrip_without_reuse() {
    let key = CryptoKey::from_bytes(&[7u8; 32]).unwrap();
    let mut allocator = DurableAllocator { next: 1 };
    let first = HandshakeEnvelope::seal_with_allocator(&key, Role::Host, "host-1", &mut allocator, b"one").unwrap();
    let reloaded = CryptoKey::from_bytes(&[7u8; 32]).unwrap();
    let second = HandshakeEnvelope::seal_with_allocator(&reloaded, Role::Host, "host-1", &mut allocator, b"two").unwrap();
    assert_ne!(first.nonce(), second.nonce());
    assert_eq!(first.open(&key, Role::Host, "host-1").unwrap(), b"one");
    assert_eq!(second.open(&key, Role::Host, "host-1").unwrap(), b"two");
}

#[test]
fn malformed_envelopes_are_rejected() {
    assert!(matches!(HandshakeEnvelope::from_bytes(b"LS"), Err(CryptoError::MalformedEnvelope)));
    let key = key();
    let envelope = HandshakeEnvelope::seal(&key, Role::Host, "host-1", b"hello").unwrap();
    let mut bytes = envelope.as_bytes().to_vec();
    bytes[0] = b'X';
    assert!(matches!(HandshakeEnvelope::from_bytes(&bytes), Err(CryptoError::MalformedEnvelope)));
}

#[test]
fn wrong_key_cannot_open_envelope() {
    let envelope = HandshakeEnvelope::seal(&key(), Role::Host, "host-1", b"hello").unwrap();
    assert!(matches!(envelope.open(&CryptoKey::from_bytes(&[8u8; 32]).unwrap(), Role::Host, "host-1"), Err(CryptoError::AuthenticationFailed)));
}
