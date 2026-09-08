import 'package:flutter_test/flutter_test.dart';
import 'package:localscale_desktop/local_agent_api.dart';
import 'package:localscale_desktop/test_pairing_bootstrap.dart';

const _onion = 'abcdefghijklmnopqrstuvwxabcdefghijklmnopqrstuvwxyz234567.onion';

const _enabledConfig = TestPairingConfig(
  enabled: true,
  hostNodeId: 'linux-host',
  clientNodeId: 'mac-client',
  hostOnionEndpoint: _onion,
  invitationSecret: 'test-invitation-secret',
);

void main() {
  test('disabled profile never contacts the local agent', () async {
    final api = _RecordingApi();

    final outcome = await TestPairingBootstrap(api).run(
      config: const TestPairingConfig(
        enabled: false,
        hostNodeId: '',
        clientNodeId: '',
        hostOnionEndpoint: '',
        invitationSecret: '',
      ),
      platform: TestPairingPlatform.linux,
    );

    expect(outcome, TestPairingOutcome.disabled);
    expect(api.calls, isEmpty);
  });

  test('Linux host configures, approves, then starts through the agent API',
      () async {
    final api = _RecordingApi();

    final outcome = await TestPairingBootstrap(api).run(
      config: _enabledConfig,
      platform: TestPairingPlatform.linux,
    );

    expect(outcome, TestPairingOutcome.running);
    expect(api.mode, LocalScaleMode.host);
    expect(api.configRole, 'host');
    expect(api.configNodeId, 'linux-host');
    expect(api.configHostNodeId, isNull);
    expect(api.configVirtualIp, '10.42.0.1');
    expect(api.calls, ['mode', 'config', 'approve', 'start']);
  });

  test('macOS client uses the Host invitation and its own node identity',
      () async {
    final api = _RecordingApi();

    final outcome = await TestPairingBootstrap(api).run(
      config: _enabledConfig,
      platform: TestPairingPlatform.macOS,
    );

    expect(outcome, TestPairingOutcome.running);
    expect(api.mode, LocalScaleMode.cliente);
    expect(api.configRole, 'cliente');
    expect(api.configNodeId, 'mac-client');
    expect(api.configHostNodeId, 'linux-host');
    expect(api.configVirtualIp, '10.42.0.2');
  });

  test('restart-required configuration is approved then schedules reload',
      () async {
    final api = _RecordingApi(
      approveResult: const PeerStatus(
        configured: true,
        transport: 'restart_required',
        connected: false,
        approved: true,
      ),
    );

    final outcome = await TestPairingBootstrap(api).run(
      config: _enabledConfig,
      platform: TestPairingPlatform.linux,
    );

    expect(outcome, TestPairingOutcome.restartScheduled);
    expect(api.calls, ['mode', 'config', 'approve', 'restart']);
  });

  test('incomplete or unsupported profiles fail before an agent mutation',
      () async {
    final incompleteApi = _RecordingApi();
    await expectLater(
      TestPairingBootstrap(incompleteApi).run(
        config: const TestPairingConfig(
          enabled: true,
          hostNodeId: 'same',
          clientNodeId: 'same',
          hostOnionEndpoint: 'not-an-onion',
          invitationSecret: '',
        ),
        platform: TestPairingPlatform.linux,
      ),
      throwsFormatException,
    );
    expect(incompleteApi.calls, isEmpty);

    final unsupportedApi = _RecordingApi();
    await expectLater(
      TestPairingBootstrap(unsupportedApi).run(
        config: _enabledConfig,
        platform: TestPairingPlatform.unsupported,
      ),
      throwsUnsupportedError,
    );
    expect(unsupportedApi.calls, isEmpty);
  });
}

class _RecordingApi implements LocalAgentApi {
  _RecordingApi({PeerStatus? approveResult})
      : _approveResult = approveResult ??
            const PeerStatus(
              configured: true,
              transport: 'unavailable',
              connected: false,
              approved: true,
            );

  final calls = <String>[];
  final PeerStatus _approveResult;
  LocalScaleMode? mode;
  String? configRole;
  String? configNodeId;
  String? configHostNodeId;
  String? configVirtualIp;

  @override
  Future<ServiceStatus> setMode(LocalScaleMode value) async {
    calls.add('mode');
    mode = value;
    return ServiceStatus(mode: value, state: ServiceState.stopped);
  }

  @override
  Future<PeerStatus> setPeerConfig({
    required String role,
    required String nodeId,
    required String onionEndpoint,
    String? hostNodeId,
    required String invitationSecret,
    String? virtualIp,
  }) async {
    calls.add('config');
    configRole = role;
    configNodeId = nodeId;
    configHostNodeId = hostNodeId;
    configVirtualIp = virtualIp;
    return const PeerStatus(
      configured: true,
      transport: 'unavailable',
      connected: false,
      approved: false,
    );
  }

  @override
  Future<PeerStatus> approvePeer() async {
    calls.add('approve');
    return _approveResult;
  }

  @override
  Future<GeneratedInvitation> generateInvitation(
          {required String nodeId,
          String? virtualIp,
          Duration ttl = const Duration(minutes: 10)}) =>
      throw UnimplementedError();

  @override
  Future<PeerStatus> importInvitation(
          {required String nodeId,
          required String invitation,
          String? virtualIp}) =>
      throw UnimplementedError();

  @override
  Future<void> restartRuntime() async {
    calls.add('restart');
  }

  @override
  Future<ServiceStatus> start() async {
    calls.add('start');
    return ServiceStatus(mode: mode!, state: ServiceState.running);
  }

  @override
  Future<ServiceStatus> status() => throw UnimplementedError();
  @override
  Future<ServiceStatus> stop() => throw UnimplementedError();
  @override
  Future<ServiceStatus> sync() => throw UnimplementedError();
  @override
  Future<PeerStatus> peerStatus() => throw UnimplementedError();
  @override
  Future<void> setVirtualIp(String virtualIp) => throw UnimplementedError();
  @override
  Future<NetworkDevicesResponse> getDevices() => throw UnimplementedError();
  @override
  Future<PeerStatus> resetPeer() => throw UnimplementedError();
  @override
  Future<void> removeHostPeer(String nodeId) => throw UnimplementedError();
  @override
  Future<String> backendLogTail() => throw UnimplementedError();
}
