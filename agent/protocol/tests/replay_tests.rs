use localscale_agent_protocol::{Message, ReplayGuard, Role};

#[test]
fn replay_guard_rejects_nonce_reuse_inside_window() {
    let message = Message::HandshakeInit {
        node_id: "node-123".into(),
        timestamp: 1_700_000_000,
        nonce: "0123456789abcdef".into(),
    };
    let mut guard = ReplayGuard::default();
    assert!(guard.accept(&message, 1_700_000_001, Role::Host).is_ok());
    assert!(guard.accept(&message, 1_700_000_002, Role::Host).is_err());
}
