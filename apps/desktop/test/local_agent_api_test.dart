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

  test('client retrieves devices and updates virtual IP', () async {
    final transport = _DevicesTransport();
    final client = LocalAgentApiClient(transport);
    final devices = await client.getDevices();
    expect(devices.localDevice.nodeId, 'node-local');
    expect(devices.localDevice.virtualIp, '10.42.0.1');
    expect(devices.remotePeers.length, 1);
    expect(devices.remotePeers.first.nodeId, 'node-peer');

    await client.setVirtualIp('10.42.0.5');
    expect(transport.lastPostedBody, {'virtual_ip': '10.42.0.5'});
  });

  test('peer configuration and approval remain separate agent operations',
      () async {
    final transport = _PeerTransport();
    final client = LocalAgentApiClient(transport);

    final saved = await client.setPeerConfig(
      role: 'cliente',
      nodeId: 'mac-client',
      hostNodeId: 'linux-host',
      onionEndpoint:
          'abcdefghijklmnopqrstuvwxabcdefghijklmnopqrstuvwxyz234567.onion',
      invitationSecret: 'test-invitation-secret',
      virtualIp: '10.42.0.2',
    );

    expect(saved.approved, isFalse);
    expect(saved.restartRequired, isTrue);
    expect(transport.requests, hasLength(1));
    expect(transport.requests.single.path, '/api/v1/peer/config');
    expect(transport.requests.single.body, {
      'role': 'cliente',
      'node_id': 'mac-client',
      'host_node_id': 'linux-host',
      'onion_endpoint':
          'abcdefghijklmnopqrstuvwxabcdefghijklmnopqrstuvwxyz234567.onion',
      'invitation_secret': 'test-invitation-secret',
      'virtual_ip': '10.42.0.2',
    });

    final approved = await client.approvePeer();
    expect(approved.approved, isTrue);
    expect(transport.requests.last.path, '/api/v1/peer/approve');
  });

  test('invitation endpoints keep capability opaque and approval separate',
      () async {
    final transport = _InvitationTransport();
    final client = LocalAgentApiClient(transport);
    final generated = await client.generateInvitation(
        nodeId: 'linux-host', virtualIp: '10.42.0.1');
    expect(generated.invitation, 'lsinv1.opaque');
    expect(transport.requests.first.body, {
      'node_id': 'linux-host',
      'ttl_seconds': 600,
      'virtual_ip': '10.42.0.1',
    });

    final imported = await client.importInvitation(
        nodeId: 'mac-client',
        invitation: generated.invitation,
        virtualIp: '10.42.0.2');
    expect(imported.approved, isFalse);
    expect(transport.requests.last.path, '/api/v1/invitations/import');
    expect(transport.requests.last.body, {
      'node_id': 'mac-client',
      'invitation': 'lsinv1.opaque',
      'virtual_ip': '10.42.0.2',
    });
  });
}

class _RecordingTransport implements LocalAgentTransport {
  final requests = <String>[];
  final response = '{"mode":"cliente","state":"stopped","onion_endpoint":null}';

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

class _DevicesTransport implements LocalAgentTransport {
  Map<String, dynamic>? lastPostedBody;

  @override
  Future<String> get(String path) async {
    return '{"transport":"Tor v3 Onion (Strict Isolation)","isolation":"tor_only_no_lan","local_device":{"node_id":"node-local","role":"host","onion_endpoint":"local.onion","virtual_ip":"10.42.0.1","status":"active"},"remote_peers":[{"node_id":"node-peer","role":"cliente","onion_endpoint":"peer.onion","virtual_ip":"10.42.0.2","status":"approved","approved":true,"revoked":false}]}';
  }

  @override
  Future<String> post(String path, {Map<String, dynamic>? body}) async {
    lastPostedBody = body;
    return '{"status":"ok"}';
  }
}

class _RecordedRequest {
  const _RecordedRequest(this.path, this.body);
  final String path;
  final Map<String, dynamic>? body;
}

class _PeerTransport implements LocalAgentTransport {
  final requests = <_RecordedRequest>[];

  @override
  Future<String> get(String path) async =>
      '{"configured":false,"transport":"unavailable","connected":false,"approved":false}';

  @override
  Future<String> post(String path, {Map<String, dynamic>? body}) async {
    requests.add(_RecordedRequest(path, body));
    if (path == '/api/v1/peer/approve') {
      return '{"configured":true,"transport":"restart_required","connected":false,"approved":true}';
    }
    return '{"configured":true,"transport":"restart_required","connected":false,"approved":false}';
  }
}

class _InvitationTransport implements LocalAgentTransport {
  final requests = <_RecordedRequest>[];

  @override
  Future<String> get(String path) => throw UnimplementedError();

  @override
  Future<String> post(String path, {Map<String, dynamic>? body}) async {
    requests.add(_RecordedRequest(path, body));
    if (path.endsWith('/generate')) {
      return '{"version":1,"invitation":"lsinv1.opaque","expires_at":4102444800}';
    }
    return '{"configured":true,"transport":"restart_required","connected":false,"approved":false}';
  }
}
