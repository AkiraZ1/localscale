import 'package:flutter/foundation.dart';

import 'local_agent_api.dart';

enum TestPairingPlatform { linux, macOS, unsupported }

@immutable
class TestPairingConfig {
  const TestPairingConfig({
    required this.enabled,
    required this.hostNodeId,
    required this.clientNodeId,
    required this.hostOnionEndpoint,
    required this.invitationSecret,
  });

  factory TestPairingConfig.fromEnvironment() => const TestPairingConfig(
        enabled: bool.fromEnvironment('LOCALSCALE_TEST_PAIRING'),
        hostNodeId: String.fromEnvironment('LOCALSCALE_TEST_HOST_NODE_ID'),
        clientNodeId: String.fromEnvironment('LOCALSCALE_TEST_CLIENT_NODE_ID'),
        hostOnionEndpoint: String.fromEnvironment('LOCALSCALE_TEST_HOST_ONION'),
        invitationSecret:
            String.fromEnvironment('LOCALSCALE_TEST_INVITATION_SECRET'),
      );

  final bool enabled;
  final String hostNodeId;
  final String clientNodeId;
  final String hostOnionEndpoint;
  final String invitationSecret;

  static final RegExp _v3Onion = RegExp(r'^[a-z2-7]{56}\.onion$');

  bool get isComplete =>
      hostNodeId.isNotEmpty &&
      clientNodeId.isNotEmpty &&
      hostNodeId != clientNodeId &&
      _v3Onion.hasMatch(hostOnionEndpoint) &&
      invitationSecret.isNotEmpty;
}

enum TestPairingOutcome {
  disabled,
  configured,
  running,
  restartScheduled,
}

class TestPairingBootstrap {
  const TestPairingBootstrap(this.api);
  final LocalAgentApi api;

  Future<TestPairingOutcome> run({
    required TestPairingConfig config,
    required TestPairingPlatform platform,
  }) async {
    if (!config.enabled) return TestPairingOutcome.disabled;
    if (!config.isComplete) {
      throw const FormatException(
          'The opt-in test pairing profile requires all pairing dart-defines');
    }
    if (platform == TestPairingPlatform.unsupported) {
      throw UnsupportedError('Test pairing supports only Linux and macOS');
    }

    final isHost = platform == TestPairingPlatform.linux;
    await api.setMode(isHost ? LocalScaleMode.host : LocalScaleMode.cliente);
    // Keep each local action explicit. In particular, saving an invitation is
    // not consent to enable it; the next call is the opt-in approval step.
    var peer = await api.setPeerConfig(
      role: isHost ? 'host' : 'cliente',
      nodeId: isHost ? config.hostNodeId : config.clientNodeId,
      hostNodeId: isHost ? null : config.hostNodeId,
      onionEndpoint: config.hostOnionEndpoint,
      invitationSecret: config.invitationSecret,
      virtualIp: isHost ? '10.42.0.1' : '10.42.0.2',
    );

    if (!peer.approved) peer = await api.approvePeer();
    if (peer.restartRequired) {
      await api.restartRuntime();
      return TestPairingOutcome.restartScheduled;
    }

    final service = await api.start();
    return service.state == ServiceState.running
        ? TestPairingOutcome.running
        : TestPairingOutcome.configured;
  }
}
