import 'local_agent_api.dart';

Future<bool> ensureLocalAgentRunning() async => false;

Future<bool> ensureLocalAgentRestarted() async => false;

LocalAgentTransport defaultLocalAgentTransport() =>
    throw UnsupportedError('Local agent transport is unavailable on Web');
