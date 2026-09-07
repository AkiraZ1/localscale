import 'dart:convert';
import 'dart:io';
import 'local_agent_api.dart';

int nativeLocalAgentPort({required bool macOS}) => macOS ? 18765 : 8765;

typedef AgentHealthProbe = Future<bool> Function(Uri base);
typedef AgentProcessStarter = Future<void> Function(
    String executable, List<String> arguments);

/// Makes the native desktop bundle self-contained without competing with a
/// daemon already managed by systemd (or any other supervisor).
Future<bool> ensureLocalAgentRunning({
  Uri? base,
  String? resolvedExecutable,
  AgentHealthProbe? healthProbe,
  AgentProcessStarter? processStarter,
  Duration retryDelay = const Duration(milliseconds: 500),
  int attempts = 10,
}) async {
  final agentBase = base ??
      Uri(
          scheme: 'http',
          host: '127.0.0.1',
          port: nativeLocalAgentPort(macOS: Platform.isMacOS));
  final probe = healthProbe ?? _probeAgentHealth;
  if (await probe(agentBase)) {
    return true;
  }

  final desktopExecutable = resolvedExecutable ?? Platform.resolvedExecutable;
  final agentExecutable = File(
      '${File(desktopExecutable).parent.path}${Platform.pathSeparator}localscaled');
  if (!await agentExecutable.exists()) return false;

  final start = processStarter ?? _startAgentDetached;
  try {
    await start(agentExecutable.path,
        <String>['--port', '${agentBase.port}', '--no-open']);
  } catch (error, stackTrace) {
    // Keep the desktop UI available so it can report/retry an unavailable
    // agent instead of crashing during application bootstrap.
    print('Failed to start agent: $error\n$stackTrace');
    return false;
  }
  for (var attempt = 0; attempt < attempts; attempt++) {
    if (await probe(agentBase)) {
      return true;
    }
    if (attempt + 1 < attempts) await Future<void>.delayed(retryDelay);
  }
  return false;
}

/// Waits for an agent that accepted `/api/v1/runtime/restart` to leave its
/// loopback port, then accepts either a platform supervisor's replacement or
/// starts the bundled sibling agent. This is deliberately app-owned: it never
/// invokes systemd, launchd, a shell, or an arbitrary command.
Future<bool> ensureLocalAgentRestarted({
  Uri? base,
  String? resolvedExecutable,
  AgentHealthProbe? healthProbe,
  AgentProcessStarter? processStarter,
  Duration retryDelay = const Duration(milliseconds: 500),
  int shutdownAttempts = 10,
  // systemd commonly uses RestartSec=3; keep a little extra headroom before
  // falling back to a sibling process.
  int supervisorAttempts = 10,
}) async {
  final agentBase = base ??
      Uri(
          scheme: 'http',
          host: '127.0.0.1',
          port: nativeLocalAgentPort(macOS: Platform.isMacOS));
  final probe = healthProbe ?? _probeAgentHealth;
  for (var attempt = 0; attempt < shutdownAttempts; attempt++) {
    if (!await probe(agentBase)) {
      // A service manager may have observed the dedicated restart exit code
      // slightly after the port closed. Wait roughly five seconds by default
      // before launching a sibling, which avoids a bind race with
      // systemd/launchd (for example, systemd RestartSec=3).
      for (var supervisorAttempt = 0;
          supervisorAttempt < supervisorAttempts;
          supervisorAttempt++) {
        if (await probe(agentBase)) return true;
        if (supervisorAttempt + 1 < supervisorAttempts) {
          await Future<void>.delayed(retryDelay);
        }
      }
      return ensureLocalAgentRunning(
        base: agentBase,
        resolvedExecutable: resolvedExecutable,
        healthProbe: probe,
        processStarter: processStarter,
        retryDelay: retryDelay,
      );
    }
    await Future<void>.delayed(retryDelay);
  }
  return false;
}

Future<void> _startAgentDetached(
    String executable, List<String> arguments) async {
  await Process.start(executable, arguments, mode: ProcessStartMode.detached);
}

Future<bool> _probeAgentHealth(Uri base) async {
  final client = HttpClient()..connectionTimeout = const Duration(seconds: 1);
  try {
    final request = await client
        .getUrl(base.replace(path: '/health'))
        .timeout(const Duration(seconds: 1));
    final response = await request.close().timeout(const Duration(seconds: 1));
    final body = await utf8.decoder
        .bind(response)
        .join()
        .timeout(const Duration(seconds: 1));
    if (response.statusCode != HttpStatus.ok) return false;
    final json = jsonDecode(body);
    return json is Map<String, dynamic> &&
        json['status'] == 'ok' &&
        json['service'] == 'localscale';
  } on Object {
    return false;
  } finally {
    client.close(force: true);
  }
}

class HttpLocalAgentTransport implements LocalAgentTransport {
  HttpLocalAgentTransport({Uri? base})
      : base = base ??
            Uri(
                scheme: 'http',
                host: '127.0.0.1',
                port: nativeLocalAgentPort(macOS: Platform.isMacOS));
  final Uri base;
  Future<String> _request(String method, String path,
      [Map<String, dynamic>? body]) async {
    final client = HttpClient();
    try {
      final request = method == 'GET'
          ? await client.getUrl(base.replace(path: path))
          : await client.postUrl(base.replace(path: path));
      final origin = '${base.scheme}://${base.host}:${base.port}';
      if (method != 'GET') {
        request.headers
          ..set('Origin', origin)
          ..set('Referer', '$origin/');
      }
      if (body != null) {
        final bytes = utf8.encode(jsonEncode(body));
        request.headers
          ..contentType = ContentType.json
          ..contentLength = bytes.length;
        request.add(bytes);
      }
      final response = await request.close();
      final text = await utf8.decoder.bind(response).join();
      if (response.statusCode < 200 || response.statusCode >= 300) {
        throw StateError('Local agent request failed (${response.statusCode})');
      }
      return text;
    } finally {
      client.close(force: true);
    }
  }

  @override
  Future<String> get(String path) => _request('GET', path);
  @override
  Future<String> post(String path, {Map<String, dynamic>? body}) =>
      _request('POST', path, body);
}

LocalAgentTransport defaultLocalAgentTransport() => HttpLocalAgentTransport();
