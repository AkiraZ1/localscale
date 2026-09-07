use localscale_agent_protocol::{
    decode_frame, encode_frame, ClientConfig, FrameError, HostInvitation, PeerConfig, PeerRole,
    ReplayGuard, SessionNonce, ValidationError,
};

#[test]
fn length_bounded_frames_round_trip_and_reject_bad_lengths() {
    let frame = encode_frame(b"hello").unwrap();
    assert_eq!(decode_frame(&frame).unwrap(), b"hello");
    assert!(matches!(
        decode_frame(&[0, 0, 0, 5, b'h']),
        Err(FrameError::Incomplete)
    ));
    assert!(matches!(
        decode_frame(&[0xff, 0xff, 0xff, 0xff]),
        Err(FrameError::TooLarge)
    ));
    assert!(matches!(
        decode_frame(&[0, 0, 0, 0, b'x', b'e', b't', b'r', b'a']),
        Err(FrameError::TrailingBytes)
    ));
}

#[test]
fn invitation_and_client_config_validate_public_onion_and_redact_secrets() {
    let invitation = HostInvitation::new(
        "host-01",
        "abcdefghijklmnopqrstuvwxabcdefghijklmnopqrstuvwxyz234567.onion",
        "secret-token-which-must-not-leak",
    )
    .unwrap();
    let client = ClientConfig::from_invitation(&invitation, "cliente-01").unwrap();
    assert_eq!(client.role(), PeerRole::Cliente);
    assert_eq!(client.host_node_id(), "host-01");
    assert!(client.diagnostics().contains("configured"));
    assert!(!client.diagnostics().contains("secret-token"));
    assert!(HostInvitation::new("host-01", "not-an-onion", "secret").is_err());
}

#[test]
fn session_nonce_is_single_use_and_role_bound() {
    let nonce = SessionNonce::from_bytes([7u8; 32]);
    let mut guard = ReplayGuard::default();
    assert!(guard
        .accept_session(&nonce, "host-01", PeerRole::Host)
        .is_ok());
    assert!(matches!(
        guard.accept_session(&nonce, "host-01", PeerRole::Host),
        Err(ValidationError::ReplayDetected)
    ));
    assert!(guard
        .accept_session(&nonce, "host-01", PeerRole::Cliente)
        .is_err());
}

#[test]
fn peer_config_does_not_accept_host_secret_as_an_endpoint() {
    assert!(PeerConfig::client(
        "cliente-01",
        "host-01",
        "abcdefghijklmnopqrstuvwxabcdefghijklmnopqrstuvwxyz234567.onion",
        "secret-token-123456"
    )
    .is_ok());
    assert!(PeerConfig::client(
        "cliente-01",
        "host-01",
        "/var/lib/localscale/onion/hs_ed25519_secret_key",
        "secret"
    )
    .is_err());
}
