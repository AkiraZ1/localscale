// ignore_for_file: avoid_web_libraries_in_flutter, deprecated_member_use

import 'dart:convert';
import 'dart:html' as html;

import 'local_agent_api.dart';

Future<bool> ensureLocalAgentRunning() async => true;

Future<bool> ensureLocalAgentRestarted() async => true;

/// HTTP transport used by the Flutter page served from the local agent.
///
/// The page and API share the agent's origin, so this remains a loopback
/// request without hard-coding a port (the agent may be started with --port).
class HttpLocalAgentTransport implements LocalAgentTransport {
  HttpLocalAgentTransport({Uri? base}) : base = _origin(base ?? Uri.base);

  final Uri base;

  static Uri _origin(Uri uri) => uri.replace(path: '', query: '', fragment: '');

  Future<String> _request(String method, String path,
      [Map<String, dynamic>? body]) async {
    final request = await html.HttpRequest.request(
      base.replace(path: path).toString(),
      method: method,
      sendData: body == null ? null : jsonEncode(body),
      requestHeaders:
          body == null ? null : {'Content-Type': 'application/json'},
    );
    final text = request.responseText ?? '';
    final status = request.status ?? 0;
    if (status < 200 || status >= 300) {
      throw StateError('Local agent request failed ($status)');
    }
    return text;
  }

  @override
  Future<String> get(String path) => _request('GET', path);

  @override
  Future<String> post(String path, {Map<String, dynamic>? body}) =>
      _request('POST', path, body);
}

LocalAgentTransport defaultLocalAgentTransport() => HttpLocalAgentTransport();
