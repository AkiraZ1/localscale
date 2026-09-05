use localscale_agent_protocol::{parse_message, validate_message, Message, ParseError, Role};

#[test]
fn parses_versioned_handshake_message() {
    let message = parse_message(b"v1|handshake|init|node-123|1700000000|0123456789abcdef").unwrap();
    assert_eq!(message, Message::HandshakeInit {
        node_id: "node-123".into(),
        timestamp: 1_700_000_000,
        nonce: "0123456789abcdef".into(),
    });
}

#[test]
fn rejects_unknown_version() {
    assert!(matches!(parse_message(b"v2|keepalive|node-123|1700000000"), Err(ParseError::UnsupportedVersion(2))));
}

#[test]
fn validates_node_identity_and_nonce() {
    let message = Message::HandshakeInit { node_id: "node-123".into(), timestamp: 1_700_000_000, nonce: "0123456789abcdef".into() };
    assert!(validate_message(&message, 1_700_000_010, Role::Host).is_ok());
    let bad = Message::HandshakeInit { node_id: "../escape".into(), timestamp: 1_700_000_000, nonce: "0123456789abcdef".into() };
    assert!(validate_message(&bad, 1_700_000_010, Role::Host).is_err());
}

#[test]
fn rejects_replayed_or_expired_handshake() {
    let message = Message::HandshakeInit { node_id: "node-123".into(), timestamp: 1_700_000_000, nonce: "0123456789abcdef".into() };
    assert!(validate_message(&message, 1_700_000_301, Role::Host).is_err());
}

#[test]
fn enforces_handshake_phase_and_role_restrictions() {
    let response = Message::HandshakeResponse { node_id: "node-123".into(), timestamp: 1_700_000_000, nonce: "0123456789abcdef".into() };
    assert!(validate_message(&response, 1_700_000_001, Role::Host).is_err());
    assert!(validate_message(&response, 1_700_000_001, Role::Cliente).is_ok());
}

#[test]
fn validates_keepalive_and_mtu() {
    let keepalive = Message::Keepalive { node_id: "node-123".into(), timestamp: 1_700_000_000 };
    assert!(validate_message(&keepalive, 1_700_000_001, Role::Host).is_ok());
    let mtu = Message::MtuProbe { node_id: "node-123".into(), mtu: 1500 };
    assert!(validate_message(&mtu, 1_700_000_001, Role::Cliente).is_ok());
    let invalid = Message::MtuProbe { node_id: "node-123".into(), mtu: 65_535 };
    assert!(validate_message(&invalid, 1_700_000_001, Role::Cliente).is_err());
}

#[test]
fn cryptographic_provider_loads_a_v1_key() {
    let key = localscale_agent_protocol::CryptoProvider::load_key(&[7u8; 32]).unwrap();
    assert_eq!(key.to_bytes(), [7u8; 32]);
}
