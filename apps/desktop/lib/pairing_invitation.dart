import 'dart:convert';

import 'package:crypto/crypto.dart';

/// Public, untrusted fields shown before an invitation is submitted.
/// Authenticity, expiry and replay are always checked by the local Rust agent.
class InvitationPreview {
  const InvitationPreview({
    required this.hostNodeId,
    required this.onionEndpoint,
    required this.expiresAt,
    required this.fingerprint,
  });

  final String hostNodeId;
  final String onionEndpoint;
  final DateTime expiresAt;
  final String fingerprint;

  static final _onion = RegExp(r'^[a-z2-7]{56}\.onion$');

  static InvitationPreview parse(String value) {
    final invitation = value.trim();
    const prefix = 'lsinv1.';
    if (!invitation.startsWith(prefix)) {
      throw const FormatException('Convite LocalScale inválido');
    }
    Object? decoded;
    try {
      decoded = jsonDecode(utf8.decode(base64Url
          .decode(base64Url.normalize(invitation.substring(prefix.length)))));
    } on Object {
      throw const FormatException('Convite LocalScale malformado');
    }
    if (decoded is! Map<String, dynamic>) {
      throw const FormatException('Convite LocalScale malformado');
    }
    final version = decoded['version'] ?? decoded['v'];
    final host = decoded['host_node_id'] ?? decoded['node_id'];
    final onion = decoded['onion_endpoint'] ?? decoded['endpoint'];
    final expiry = decoded['expires_at'];
    if (version != 1 ||
        host is! String ||
        host.trim().isEmpty ||
        onion is! String ||
        !_onion.hasMatch(onion) ||
        expiry is! int) {
      throw const FormatException('Campos públicos do convite são inválidos');
    }
    // This is a comparison code, not an authenticity decision. Including the
    // complete opaque envelope makes it stable even if the backend schema adds
    // public fields; the backend remains the trust boundary.
    final digest = sha256.convert(utf8.encode(invitation)).bytes;
    final fingerprint = digest
        .take(8)
        .map((byte) => byte.toRadixString(16).padLeft(2, '0'))
        .join()
        .replaceAllMapped(RegExp(r'.{4}'), (match) => '${match.group(0)} ')
        .trim()
        .toUpperCase();
    return InvitationPreview(
      hostNodeId: host,
      onionEndpoint: onion,
      expiresAt:
          DateTime.fromMillisecondsSinceEpoch(expiry * 1000, isUtc: true),
      fingerprint: fingerprint,
    );
  }
}
