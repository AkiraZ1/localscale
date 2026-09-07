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
    expect(request.headers.value('Referer'),
        'http://${InternetAddress.loopbackIPv4.host}:$serverPort/');
    expect(body, expectedBody);
  });

  test('does not launch a second agent when health probe succeeds', () async {
    var starts = 0;
    final healthy = await ensureLocalAgentRunning(
      base: Uri.parse('http://127.0.0.1:8765'),
      healthProbe: (_) async => true,
      processStarter: (_, __) async => starts++,
    );

    expect(healthy, isTrue);
    expect(starts, 0);
  });

  test('launches sibling localscaled with the selected port and no-open',
      () async {
    final temp = await Directory.systemTemp.createTemp('localscale-launcher-');
    addTearDown(() => temp.delete(recursive: true));
    final desktop = File('${temp.path}/localscale_desktop');
    final agent = File('${temp.path}/localscaled');
    await desktop.writeAsString('desktop');
    await agent.writeAsString('agent');
    var probes = 0;
    String? executable;
    List<String>? arguments;

    final healthy = await ensureLocalAgentRunning(
      base: Uri.parse('http://127.0.0.1:18765'),
      resolvedExecutable: desktop.path,
      healthProbe: (_) async => ++probes >= 2,
      processStarter: (path, args) async {
        executable = path;
        arguments = args;
      },
      retryDelay: Duration.zero,
    );

    expect(healthy, isTrue);
    expect(executable, agent.path);
    expect(arguments, ['--port', '18765', '--no-open']);
  });

  test('restart waits for the old agent before accepting a supervisor restart',
      () async {
    final answers = <bool>[true, false, true].iterator;
    var starts = 0;

    final restarted = await ensureLocalAgentRestarted(
      base: Uri.parse('http://127.0.0.1:8765'),
      healthProbe: (_) async {
        answers.moveNext();
        return answers.current;
      },
      processStarter: (_, __) async => starts++,
      retryDelay: Duration.zero,
      supervisorAttempts: 1,
    );

    expect(restarted, isTrue);
    expect(starts, 0);
  });

  test('restart accepts a supervisor that returns after a delayed restart',
      () async {
    var probes = 0;
    var starts = 0;

    final restarted = await ensureLocalAgentRestarted(
      base: Uri.parse('http://127.0.0.1:8765'),
      healthProbe: (_) async {
        probes++;
        // Healthy old agent, then down, then twenty supervisor-wait probes
        // (more than a simulated three-second RestartSec) before recovery.
        return probes == 1 || probes > 22;
      },
      processStarter: (_, __) async => starts++,
      retryDelay: Duration.zero,
      supervisorAttempts: 35,
    );

    expect(restarted, isTrue);
    expect(starts, 0);
  });

  test('restart launches the bundled agent when no supervisor replaces it',
      () async {
    final temp = await Directory.systemTemp.createTemp('localscale-restart-');
    addTearDown(() => temp.delete(recursive: true));
    final desktop = File('${temp.path}/localscale_desktop');
    final agent = File('${temp.path}/localscaled');
    await desktop.writeAsString('desktop');
    await agent.writeAsString('agent');
    // Old agent healthy, then shutdown, no supervisor replacement during the
    // grace probe or the fallback's initial probe, then the launched sibling
    // becomes healthy.
    final answers = <bool>[true, false, false, false, true].iterator;
    var starts = 0;

    final restarted = await ensureLocalAgentRestarted(
      base: Uri.parse('http://127.0.0.1:8765'),
      resolvedExecutable: desktop.path,
      healthProbe: (_) async {
        answers.moveNext();
        return answers.current;
      },
      processStarter: (_, __) async => starts++,
      retryDelay: Duration.zero,
      supervisorAttempts: 1,
    );

    expect(restarted, isTrue);
    expect(starts, 1);
  });
}
