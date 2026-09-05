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
}

class FakeLocalAgentTransport implements LocalAgentTransport {
  FakeLocalAgentTransport(
      {this.initial = const ServiceStatus(
          mode: LocalScaleMode.cliente, state: ServiceState.stopped)})
      : current = initial;

  final ServiceStatus initial;
  ServiceStatus current;

  String _encode() => jsonEncode({
        'mode': current.mode.name,
        'state': current.state.name,
        'onion_endpoint': current.onionEndpoint,
      });

  @override
  Future<String> get(String path) async => _encode();

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
    }
    return _encode();
  }
}
