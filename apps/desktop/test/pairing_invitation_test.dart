import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:localscale_desktop/pairing_invitation.dart';

void main() {
  String invitation(Map<String, Object> payload) =>
      'lsinv1.${base64Url.encode(utf8.encode(jsonEncode(payload))).replaceAll('=', '')}';

  test('extracts only public invitation preview fields', () {
    final preview = InvitationPreview.parse(invitation({
      'version': 1,
      'invitation_id': 'opaque-id',
      'host_node_id': 'linux-host',
      'onion_endpoint':
          'abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion',
      'invitation_secret': 'never-exposed-by-preview',
      'issued_at': 1700000000,
      'expires_at': 4102444800,
    }));
    expect(preview.hostNodeId, 'linux-host');
    expect(preview.onionEndpoint, endsWith('.onion'));
    expect(preview.expiresAt.year, 2100);
    expect(preview.fingerprint, matches(RegExp(r'^[0-9A-F ]{19}$')));
  });

  test('rejects malformed and non-v3 invitations locally', () {
    expect(() => InvitationPreview.parse('hello'), throwsFormatException);
    expect(
        () => InvitationPreview.parse(invitation({
              'version': 1,
              'host_node_id': 'host',
              'onion_endpoint': 'short.onion',
              'expires_at': 4102444800,
            })),
        throwsFormatException);
  });
}
