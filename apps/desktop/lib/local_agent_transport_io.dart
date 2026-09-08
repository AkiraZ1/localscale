import 'dart:async';
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
  var agentExecutable = File(
      '${File(desktopExecutable).parent.path}${Platform.pathSeparator}localscaled');
  
  if (!await agentExecutable.exists() && Platform.isLinux) {
    const standardPaths = [
      '/usr/local/bin/localscaled',
      '/usr/bin/localscaled',
      '/opt/localscale/bin/localscaled',
    ];
    for (final path in standardPaths) {
      final file = File(path);
      if (await file.exists()) {
        agentExecutable = file;
        break;
      }
    }
    if (!await agentExecutable.exists()) {
      final home = Platform.environment['HOME'];
      if (home != null) {
        agentExecutable = File('$home/.local/opt/localscale-agent/localscaled');
      }
    }
  }

  if (!await agentExecutable.exists()) return false;

  // The health probe above failed, meaning either nothing is listening on
  // this port, or something is listening but not answering as our own
  // agent (a stuck/orphaned previous run — e.g. its shell was closed
  // without a clean shutdown, or a crash left it and its bundled Tor
  // process behind holding the port). Clear any such leftovers from this
  // exact bundled binary before starting a fresh one, so a fresh launch
  // never silently fails to bind or ends up talking to a dead process.
  await _killStaleAgentProcesses(agentExecutable);

  if (Platform.isMacOS) {
    // Fire-and-forget: this shows a native admin-password dialog the first
    // time (or after a binary update), which must never block the app's
    // own startup or ordinary (non-TUN) pairing — those work with no
    // privilege at all. If the user approves it, the *next* restart of the
    // peer transport (which already retries on its own) picks up the
    // newly-privileged binary and the TUN bridge starts working; if they
    // dismiss it, everything else keeps working without a virtual network.
    unawaited(_ensureMacOSTunPrivilege(agentExecutable));
  }

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

/// Terminates any process still running from this exact bundled agent
/// binary (matched by its own full path, never a generic process name) —
/// covers a previous run left behind by a closed terminal, a crashed
/// desktop app, or any other path that skipped a clean shutdown. Safe by
/// construction: it can only ever match this app's own bundled
/// `localscaled` and its bundled Tor child, never an unrelated process.
Future<void> _killStaleAgentProcesses(File agentExecutable) async {
  if (!Platform.isMacOS && !Platform.isLinux) return;
  try {
    await Process.run('pkill', ['-9', '-f', agentExecutable.path]);
    // The bundled Tor child is a grandchild process spawned by localscaled,
    // not something `pkill -f <agent path>` matches — its own command line
    // instead references the Tor binary bundled next to the agent (see
    // resolve_bundled_tor). Clear it too, or the fresh agent about to start
    // can fail to bind Tor's SOCKS/control ports.
    final bundleDir = agentExecutable.parent.path;
    await Process.run('pkill', ['-9', '-f', '$bundleDir/../Resources/tor/tor']);
    await Process.run('pkill', ['-9', '-f', '$bundleDir/tor/tor']);
    // Give the OS a moment to actually release the port before the fresh
    // agent tries to bind it.
    await Future<void>.delayed(const Duration(milliseconds: 300));
  } on Object {
    // Best-effort cleanup only — never block startup on this failing (e.g.
    // pkill not installed, or nothing to kill in the first place).
  }
}

/// macOS has no per-binary capability grant like Linux's `setcap` — opening
/// a `utun` control socket (see `tun_macos.rs`, used by the opt-in virtual
/// network bridge) requires root. Rather than ask the user to run a
/// terminal install script — infeasible for someone who just dragged the
/// app out of a DMG — set the setuid bit on the bundled agent binary once,
/// via the same native "app wants to make changes" dialog macOS shows for
/// any admin-privileged action. Every launch after that is a no-op: the
/// setuid bit is already there, so no further dialog appears.
Future<void> _ensureMacOSTunPrivilege(File executable) async {
  try {
    const setuidBit = 0x800; // POSIX S_ISUID
    final stat = await executable.stat();
    if ((stat.mode & setuidBit) != 0) return;
    final path = executable.path;
    final shellCommand =
        "chown root:wheel '${path.replaceAll("'", "'\\''")}' && chmod u+s '${path.replaceAll("'", "'\\''")}'";
    final appleScriptSafeCommand =
        shellCommand.replaceAll('\\', '\\\\').replaceAll('"', '\\"');
    final result = await Process.run('osascript', [
      '-e',
      'do shell script "$appleScriptSafeCommand" with administrator privileges '
          'with prompt "LocalScale precisa de uma permissão única para habilitar a rede virtual entre seus dispositivos."',
    ]);
    if (result.exitCode != 0) {
      print('LocalScale: could not grant TUN privilege: ${result.stderr}');
    }
  } catch (error) {
    print('LocalScale: TUN privilege check failed: $error');
  }
}

Future<void> _startAgentDetached(
    String executable, List<String> arguments) async {
  await Process.start(executable, arguments, mode: ProcessStartMode.detached);
}

Future<bool> _probeAgentHealth(Uri base) async {
  final client = HttpClient()
    ..connectionTimeout = const Duration(seconds: 1)
    ..findProxy = (uri) => 'DIRECT';
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
    final client = HttpClient()..findProxy = (uri) => 'DIRECT';
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
