import 'dart:convert';
import 'dart:io';
import 'local_agent_api.dart';

class HttpLocalAgentTransport implements LocalAgentTransport {
  HttpLocalAgentTransport({Uri? base})
      : base = base ?? Uri(scheme: 'http', host: '127.0.0.1', port: 8765);
  final Uri base;
  Future<String> _request(String method, String path,
      [Map<String, dynamic>? body]) async {
    final client = HttpClient();
    try {
      final request = method == 'GET'
          ? await client.getUrl(base.replace(path: path))
          : await client.postUrl(base.replace(path: path));
      if (body != null) {
        request.headers.contentType = ContentType.json;
        request.write(jsonEncode(body));
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
