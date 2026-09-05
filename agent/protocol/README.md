# LocalScale agent protocol

This directory contains the versioned LocalScale agent protocol boundary.

## Version 1 wire forms

Messages are strict UTF-8 ASCII-token records separated by `|`:

- `v1|handshake|init|<node-id>|<unix-seconds>|<hex-nonce>` — Host receives an init.
- `v1|handshake|response|<node-id>|<unix-seconds>|<hex-nonce>` — Cliente receives a response.
- `v1|keepalive|<node-id>|<unix-seconds>` — either role may use keepalive.
- `v1|mtu|<node-id>|<mtu>` — MTU probe, bounded to 576..=9000 bytes.

Node IDs are 1–128 ASCII alphanumeric, `-`, `_`, or `.` characters. Nonces are
16–128 hexadecimal characters. Timestamps must be within `REPLAY_WINDOW_SECS`
(300 seconds) of the verifier's clock. `ReplayGuard` additionally rejects nonce
reuse until its in-memory entry ages out. The role name is intentionally `Cliente`
for the protocol contract.

## Authenticated LocalScale v1 envelope

`HandshakeEnvelope` is an authenticated-encryption envelope using the maintained
Rust crates `chacha20poly1305 = 0.10.1`, `rand = 0.8.5`, and `zeroize = 1.8.1` (exact pins are in `Cargo.toml`). XChaCha20-Poly1305
provides a 256-bit key, 192-bit nonce, confidentiality, and an authentication tag;
no locally invented cryptography or fallback is used. `OsRng` supplies random
nonces for `HandshakeEnvelope::seal`. `seal_with_nonce` exists for deterministic
interoperability tests and still rejects reuse per `CryptoKey`.

`CryptoKey::generate` creates a key, while `CryptoKey::from_bytes` and
`CryptoProvider::load_key` accept exactly 32 bytes. The secret is held in
`zeroize::Zeroizing<[u8; 32]>` and is cleared on drop. `to_bytes` should only be
used for explicit key storage/transport decisions by the caller.

The serialized envelope is:

```
LSV1 | role:u8 | node_len:u16be | node_id | nonce:24 | ciphertext_len:u32be | ciphertext+tag
```

The AEAD associated data is `LS || version:u8 || role:u8 || node_id`, binding the
protocol version, role, and node identity. `open` requires the expected role and
node ID; wrong role, wrong node, wrong key, tag failure, and ciphertext tampering
all return `CryptoError::AuthenticationFailed`. Truncated, invalid, or otherwise
malformed encodings return `CryptoError::MalformedEnvelope` before decryption.
Nonce reuse on encryption returns `CryptoError::NonceReuse`; the registry is only
in memory and bounded to 4096 entries. Raw-key loading does **not** enable sealing:
`CryptoKey::from_bytes` is safe for opening only and `seal`/`seal_with_nonce` return
`CryptoError::UnsafeNoncePolicy`. To seal with a persisted key, implement
`NonceAllocator` over caller-owned crash-safe durable state and call
`HandshakeEnvelope::seal_with_allocator`; persist the allocation before exposing
the envelope. `seal_with_nonce` remains available for generated keys and tests. `CryptoError` deliberately does not expose lower-level
authentication failure details.

The envelope authenticates and encrypts handshake payloads, but it is not a key
exchange. Key provisioning, rotation, persistence, and transport replay policy
remain responsibilities of the agent/session layer; `ReplayGuard` remains the
in-memory protocol replay check and likewise does not survive restart.

## Security boundary

Parsing and validation are input hygiene and protocol-shape checks. Secure
handshake payloads must use `HandshakeEnvelope`; plaintext records must not be
sent over an untrusted transport as if they were secure.
