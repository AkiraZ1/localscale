import 'dart:convert';

enum LocalScaleMode { host, cliente }

enum ServiceState { stopped, starting, running, stopping, error }

class ServiceStatus {
  const ServiceStatus(
      {required this.mode, required this.state, this.onionEndpoint});

  final LocalScaleMode mode;
  final ServiceState state;
  final String? onionEndpoint;

  factory ServiceStatus.fromJson(Map<String, dynamic> json) {
    final mode = switch (json['mode']) {
      'host' => LocalScaleMode.host,
      'cliente' => LocalScaleMode.cliente,
      _ => throw FormatException('Unknown LocalScale mode: ${json['mode']}'),
    };
    final state = switch (json['state']) {
      'stopped' => ServiceState.stopped,
      'starting' => ServiceState.starting,
      'running' => ServiceState.running,
      'stopping' => ServiceState.stopping,
      'error' => ServiceState.error,
      _ => throw FormatException(
          'Unknown LocalScale service state: ${json['state']}'),
    };
    final endpoint = json['onion_endpoint'];
    if (endpoint != null && endpoint is! String) {
      throw const FormatException('onion_endpoint must be a string or null');
    }
    return ServiceStatus(
        mode: mode, state: state, onionEndpoint: endpoint as String?);
  }
}

class NetworkDevice {
  const NetworkDevice({
    required this.nodeId,
    required this.role,
    required this.onionEndpoint,
    required this.virtualIp,
    required this.status,
    required this.isLocal,
  });

  final String nodeId;
  final String role;
  final String? onionEndpoint;
  final String? virtualIp;
  final String status;
  final bool isLocal;

  factory NetworkDevice.fromJson(Map<String, dynamic> json, {bool isLocal = false}) {
    return NetworkDevice(
      nodeId: (json['node_id'] as String?) ?? (isLocal ? 'local-node' : 'peer-node'),
      role: (json['role'] as String?) ?? 'node',
      onionEndpoint: json['onion_endpoint'] as String?,
      virtualIp: json['virtual_ip'] as String?,
      status: (json['status'] as String?) ?? (isLocal ? 'active' : 'connected'),
      isLocal: isLocal,
    );
  }
}

class NetworkDevicesResponse {
  const NetworkDevicesResponse({
    required this.transport,
    required this.isolation,
    required this.localDevice,
    required this.remotePeers,
  });

  final String transport;
  final String isolation;
  final NetworkDevice localDevice;
  final List<NetworkDevice> remotePeers;

  factory NetworkDevicesResponse.fromJson(Map<String, dynamic> json) {
    final localJson = (json['local_device'] as Map<String, dynamic>?) ?? {};
    final peersJson = (json['remote_peers'] as List<dynamic>?) ?? [];
    return NetworkDevicesResponse(
      transport: (json['transport'] as String?) ?? 'Tor v3 Onion (Strict Isolation)',
      isolation: (json['isolation'] as String?) ?? 'tor_only_no_lan',
      localDevice: NetworkDevice.fromJson(localJson, isLocal: true),
      remotePeers: peersJson
          .whereType<Map<String, dynamic>>()
          .map((p) => NetworkDevice.fromJson(p, isLocal: false))
          .toList(),
    );
  }
}

abstract interface class LocalAgentTransport {
  Future<String> get(String path);
  Future<String> post(String path, {Map<String, dynamic>? body});
}

abstract interface class LocalAgentApi {
  Future<ServiceStatus> status();
  Future<ServiceStatus> setMode(LocalScaleMode mode);
  Future<ServiceStatus> start();
  Future<ServiceStatus> stop();
  Future<ServiceStatus> sync();
  Future<NetworkDevicesResponse> getDevices();
  Future<void> setVirtualIp(String virtualIp);
}

class LocalAgentApiClient implements LocalAgentApi {
  LocalAgentApiClient(this.transport);
  final LocalAgentTransport transport;

  Future<ServiceStatus> _parse(Future<String> response) async {
    final value = jsonDecode(await response);
    if (value is! Map<String, dynamic>) {
      throw const FormatException(
          'LocalScale agent response must be an object');
    }
    return ServiceStatus.fromJson(value);
  }

  @override
  Future<ServiceStatus> status() => _parse(transport.get('/api/v1/status'));

  @override
  Future<ServiceStatus> setMode(LocalScaleMode mode) =>
      _parse(transport.post('/api/v1/mode', body: {'mode': mode.name}));

  @override
  Future<ServiceStatus> start() =>
      _parse(transport.post('/api/v1/service/start'));

  @override
  Future<ServiceStatus> stop() =>
      _parse(transport.post('/api/v1/service/stop'));

  @override
  Future<ServiceStatus> sync() => _parse(transport.post('/api/v1/sync'));

  @override
  Future<NetworkDevicesResponse> getDevices() async {
    final raw = await transport.get('/api/v1/devices');
    final json = jsonDecode(raw);
    if (json is! Map<String, dynamic>) {
      throw const FormatException('devices response must be an object');
    }
    return NetworkDevicesResponse.fromJson(json);
  }

  @override
  Future<void> setVirtualIp(String virtualIp) async {
    await transport.post('/api/v1/peer/virtual-ip', body: {'virtual_ip': virtualIp});
  }
}

class FakeLocalAgentTransport implements LocalAgentTransport {
  FakeLocalAgentTransport(
      {this.initial = const ServiceStatus(
          mode: LocalScaleMode.cliente, state: ServiceState.stopped),
       this.initialVirtualIp = '10.42.0.1'})
      : current = initial,
        virtualIp = initialVirtualIp;

  final ServiceStatus initial;
  final String? initialVirtualIp;
  ServiceStatus current;
  String? virtualIp;

  String _encode() => jsonEncode({
        'mode': current.mode.name,
        'state': current.state.name,
        'onion_endpoint': current.onionEndpoint,
      });

  @override
  Future<String> get(String path) async {
    if (path == '/api/v1/devices') {
      return jsonEncode({
        'transport': 'Tor v3 Onion (Strict Isolation)',
        'isolation': 'tor_only_no_lan',
        'local_device': {
          'node_id': 'local-node-test',
          'role': current.mode.name,
          'onion_endpoint': current.onionEndpoint,
          'virtual_ip': virtualIp,
          'status': 'active',
        },
        'remote_peers': [
          {
            'node_id': 'remote-node-test',
            'role': current.mode == LocalScaleMode.host ? 'cliente' : 'host',
            'onion_endpoint': 'remotetest.onion',
            'virtual_ip': virtualIp == '10.42.0.1' ? '10.42.0.2' : '10.42.0.1',
            'status': 'connected',
            'approved': true,
            'revoked': false,
          }
        ],
      });
    }
    return _encode();
  }

  @override
  Future<String> post(String path, {Map<String, dynamic>? body}) async {
    if (path == '/api/v1/mode') {
      current = ServiceStatus(
          mode: body?['mode'] == 'host'
              ? LocalScaleMode.host
              : LocalScaleMode.cliente,
          state: current.state,
          onionEndpoint: current.onionEndpoint);
    } else if (path.endsWith('/start')) {
      current = ServiceStatus(
          mode: current.mode,
          state: ServiceState.running,
          onionEndpoint:
              current.mode == LocalScaleMode.host ? 'pending.onion' : null);
    } else if (path.endsWith('/stop')) {
      current = ServiceStatus(
          mode: current.mode,
          state: ServiceState.stopped,
          onionEndpoint: current.onionEndpoint);
    } else if (path == '/api/v1/peer/virtual-ip') {
      virtualIp = body?['virtual_ip'] as String?;
      return jsonEncode({'status': 'ok', 'virtual_ip': virtualIp});
    }
    return _encode();
  }
}
