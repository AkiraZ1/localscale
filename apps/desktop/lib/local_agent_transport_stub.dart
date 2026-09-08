import 'local_agent_api.dart';

String? lastAgentStartupError;

Future<bool> hasVirtualNetworkPrivilege() async => false;

Future<bool> requestVirtualNetworkPrivilege() async => false;

Future<bool> ensureLocalAgentRunning() async => false;

Future<bool> ensureLocalAgentRestarted() async => false;

LocalAgentTransport defaultLocalAgentTransport() =>
    throw UnsupportedError('Local agent transport is unavailable on Web');
