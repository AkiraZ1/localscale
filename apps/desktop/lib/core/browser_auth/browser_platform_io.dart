import 'dart:convert';
import 'dart:io';
import 'browser_auth.dart';

class IoBrowserLauncher implements BrowserLauncher {
  @override
  Future<void> launch(Uri url) async {
    final command = Platform.isMacOS
        ? 'open'
        : Platform.isWindows
            ? 'start'
            : 'xdg-open';
    await Process.start(command, [url.toString()],
        runInShell: Platform.isWindows);
  }
}

class LoopbackReceiver implements DynamicAuthCallbackReceiver {
  LoopbackReceiver() : _ready = _bind();
  final Future<HttpServer> _ready;
  static Future<HttpServer> _bind() =>
      HttpServer.bind(InternetAddress.loopbackIPv4, 0);

  @override
  Future<Uri?> waitForCallback() async {
    final server = await _ready;
    try {
      final request = await server.first;
      final uri = request.uri;
      if (uri.path != '/oauth/callback') {
        return null;
      }
      request.response.statusCode = 200;
      request.response.headers.contentType = ContentType.html;
      request.response.write(
          '<!doctype html><title>LocalScale</title>Authentication complete. You may close this window.');
      await request.response.close();
      return uri;
    } finally {
      await server.close(force: true);
    }
  }

  @override
  Future<Uri> callbackUri() async {
    final server = await _ready;
    return Uri.parse('http://127.0.0.1:${server.port}/oauth/callback');
  }
}

class HttpLocalSessionBridge implements AuthorizationCodeExchanger {
  HttpLocalSessionBridge(this.agentBase);
  final Uri agentBase;
  @override
  Future<SecureSession> exchange(
      {required String code, required String verifier}) async {
    final client = HttpClient();
    try {
      final uri = agentBase.replace(
          path: '/auth/session/bridge', queryParameters: {'handoff': code});
      final response = await (await client.getUrl(uri)).close();
      final body = await utf8.decoder.bind(response).join();
      if (response.statusCode != 200) {
        throw StateError(
            'Local agent session unavailable (${response.statusCode})');
      }
      final json = jsonDecode(body) as Map<String, dynamic>;
      final id = json['session_id'];
      final expires = json['expires_at'];
      if (id is! String || id.isEmpty || expires is! num) {
        throw const FormatException('Invalid opaque session response');
      }
      return SecureSession(
          sessionId: id,
          expiresAt: DateTime.fromMillisecondsSinceEpoch(expires.toInt() * 1000,
              isUtc: true));
    } finally {
      client.close(force: true);
    }
  }
}

BrowserLauncher systemBrowserLauncher() => IoBrowserLauncher();
AuthCallbackReceiver loopbackCallbackReceiver() => LoopbackReceiver();
AuthorizationCodeExchanger localSessionBridge(Uri agentBase) =>
    HttpLocalSessionBridge(agentBase);
