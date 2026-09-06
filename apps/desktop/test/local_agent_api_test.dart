import 'package:flutter_test/flutter_test.dart';
import 'package:localscale_desktop/local_agent_api.dart';

void main() {
  test('parses a running Host response and preserves Onion endpoint', () {
    final status = ServiceStatus.fromJson({
      'mode': 'host',
      'state': 'running',
      'onion_endpoint': 'abc123.onion',
    });
    expect(status.mode, LocalScaleMode.host);
    expect(status.state, ServiceState.running);
    expect(status.onionEndpoint, 'abc123.onion');
  });

  test('rejects unknown agent mode', () {
    expect(
        () => ServiceStatus.fromJson({'mode': 'invalid', 'state': 'stopped'}),
        throwsFormatException);
  });

  test('client maps every operation to the versioned agent contract', () async {
    final transport = _RecordingTransport();
    final client = LocalAgentApiClient(transport);
    await client.status();
    await client.setMode(LocalScaleMode.host);
    await client.start();
    await client.stop();
    await client.sync();
    expect(transport.requests, [
      'GET /api/v1/status',
      'POST /api/v1/mode {mode: host}',
      'POST /api/v1/service/start',
      'POST /api/v1/service/stop',
      'POST /api/v1/sync',
    ]);
  });
}

class _RecordingTransport implements LocalAgentTransport {
  final requests = <String>[];
  final response =
      '{"mode":"cliente","state":"stopped","onion_endpoint":null}';

  @override
  Future<String> get(String path) async {
    requests.add('GET $path');
    return response;
  }

  @override
  Future<String> post(String path, {Map<String, dynamic>? body}) async {
    requests.add('POST $path${body == null ? '' : ' $body'}');
    return response;
  }
}
