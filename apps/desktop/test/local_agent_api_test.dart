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

  test('client maps typed operations to local agent paths', () async {
    final transport = FakeLocalAgentTransport();
    final client = LocalAgentApiClient(transport);
    expect(
        (await client.setMode(LocalScaleMode.host)).mode, LocalScaleMode.host);
    expect((await client.start()).state, ServiceState.running);
    expect((await client.stop()).state, ServiceState.stopped);
  });
}
