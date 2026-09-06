import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:localscale_desktop/local_agent_transport_io.dart';

void main() {
  test('keeps the installed native agent ports', () {
    expect(nativeLocalAgentPort(macOS: false), 8765);
    expect(nativeLocalAgentPort(macOS: true), 18765);
  });

  test('POST sends a UTF-8 body with an explicit content length', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(server.close);

    final requestFuture = server.first;
    final transport = HttpLocalAgentTransport(
      base: Uri(
        scheme: 'http',
        host: InternetAddress.loopbackIPv4.host,
        port: server.port,
      ),
    );

    final serverPort = server.port;
    final responseFuture = transport.post('/control/mode', body: {
      'mode': 'host',
      'label': 'café',
    });
    final request = await requestFuture;
    final body = await utf8.decoder.bind(request).join();
    request.response
      ..statusCode = HttpStatus.ok
      ..write('{}');
    await request.response.close();
    await responseFuture;

    final expectedBody = jsonEncode({'mode': 'host', 'label': 'café'});
    expect(request.headers.contentLength, utf8.encode(expectedBody).length);
    expect(request.headers.value('Origin'),
        'http://${InternetAddress.loopbackIPv4.host}:$serverPort');
    expect(body, expectedBody);
  });
}
