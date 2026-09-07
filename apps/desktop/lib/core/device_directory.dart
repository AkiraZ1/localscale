/// Shared device/authorization boundary. Implementations must be backed by
/// control-plane endpoints; this package intentionally does not invent peers.
class IdentityKey {
  const IdentityKey({required this.issuer, required this.subject});
  final String issuer;
  final String subject;
  String get value => '$issuer|$subject';
}

class DeviceRegistration {
  const DeviceRegistration(
      {required this.deviceId,
      required this.publicKey,
      required this.identity});
  final String deviceId;
  final String publicKey;
  final IdentityKey identity;
}

class AuthorizedPeer {
  const AuthorizedPeer(
      {required this.deviceId, required this.address, required this.identity});
  final String deviceId;
  final String address;
  final IdentityKey identity;
}

abstract interface class DeviceDirectory {
  Future<void> registerCurrentDevice(DeviceRegistration registration);
  Future<List<AuthorizedPeer>> authorizedPeers(IdentityKey identity);
}
