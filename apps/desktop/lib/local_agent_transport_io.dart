import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'local_agent_api.dart';

int nativeLocalAgentPort({required bool macOS}) => macOS ? 18765 : 8765;

/// The most recent reason `ensureLocalAgentRunning` failed to actually
/// launch the agent process (as opposed to it launching but never becoming
/// healthy) — `null` while nothing has failed yet this run. The UI reads
/// this to show something more actionable than a generic "can't reach the
/// agent" when the underlying cause is known.
String? lastAgentStartupError;

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
  final agentExecutable = await _resolveAgentExecutable(resolvedExecutable);
  if (agentExecutable == null) return false;

  // A previous version of this function shelled out to `xattr -d -r
  // com.apple.quarantine` here to strip Gatekeeper quarantine from the
  // bundled agent before spawning it. That turned out to hang
  // indefinitely when invoked as a child of this app's own process — the
  // identical command runs instantly from a plain shell, so the cause was
  // never fully pinned down, but the effect was a total, silent startup
  // stall on every launch. Removed rather than patched further: the actual
  // root cause of the ad-hoc-signed child being refused at exec time was
  // hardened runtime Library Validation, not quarantine (see
  // Release.entitlements — com.apple.security.cs.disable-library-
  // validation), and approving this main app to open already clears
  // quarantine recursively across the whole bundle in practice, so this
  // extra step wasn't actually doing anything useful to begin with.

  // The health probe above failed, meaning either nothing is listening on
  // this port, or something is listening but not answering as our own
  // agent (a stuck/orphaned previous run — e.g. its shell was closed
  // without a clean shutdown, or a crash left it and its bundled Tor
  // process behind holding the port). Clear any such leftovers from this
  // exact bundled binary before starting a fresh one, so a fresh launch
  // never silently fails to bind or ends up talking to a dead process.
  await _killStaleAgentProcesses(agentExecutable);

  // Virtual-network privilege (macOS setuid grant) is requested explicitly
  // by the UI, on its own dedicated screen, only after the user chooses to
  // enable that feature and understands why — never automatically here.
  // Starting the agent itself needs no privilege at all.

  final start = processStarter ?? _startAgentDetached;
  try {
    await start(agentExecutable.path,
        <String>['--port', '${agentBase.port}', '--no-open']);
  } catch (error, stackTrace) {
    // Keep the desktop UI available so it can report/retry an unavailable
    // agent instead of crashing during application bootstrap. `print` alone
    // is invisible to a real user (no attached console) — record it
    // somewhere the UI can actually surface, since "process failed to
    // start" and "process started but never became healthy" need
    // different troubleshooting.
    lastAgentStartupError = '$error';
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

/// Finds the bundled `localscaled` binary next to this desktop executable
/// (or, on Linux, at a handful of standard install locations) — shared by
/// every function in this file that needs to locate or act on it, so the
/// search logic exists exactly once. Returns `null` if nothing was found.
Future<File?> _resolveAgentExecutable(String? resolvedExecutable) async {
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

  return await agentExecutable.exists() ? agentExecutable : null;
}

/// Whether the virtual-network feature's one-time macOS privilege grant
/// (setuid on the bundled agent) is already in place — read-only, prompts
/// nothing. The UI uses this to skip straight past the explanation/request
/// screen on every launch after the first.
Future<bool> hasVirtualNetworkPrivilege() async {
  if (!Platform.isMacOS) return true; // Linux grants this at install time.
  final agentExecutable = await _resolveAgentExecutable(null);
  if (agentExecutable == null) return false;
  const setuidBit = 0x800; // POSIX S_ISUID
  final stat = await agentExecutable.stat();
  return (stat.mode & setuidBit) != 0;
}

/// macOS has no per-binary capability grant like Linux's `setcap` — opening
/// a `utun` control socket (see `tun_macos.rs`, used by the opt-in virtual
/// network bridge) requires root. Rather than ask the user to run a
/// terminal install script — infeasible for someone who just dragged the
/// app out of a DMG — set the setuid bit on the bundled agent binary once,
/// via the same native "app wants to make changes" dialog macOS shows for
/// any admin-privileged action. Every launch after that is a no-op: the
/// setuid bit is already there, so no further dialog appears.
///
/// Called only when the user explicitly asks for the virtual-network
/// feature on its own dedicated, explained screen — never automatically at
/// startup, so the password prompt never appears out of context. Returns
/// whether the privilege ends up granted (true if it was already granted,
/// or the user approved it just now).
Future<bool> requestVirtualNetworkPrivilege() async {
  if (!Platform.isMacOS) return true;
  final agentExecutable = await _resolveAgentExecutable(null);
  if (agentExecutable == null) return false;
  try {
    const setuidBit = 0x800; // POSIX S_ISUID
    final stat = await agentExecutable.stat();
    if ((stat.mode & setuidBit) != 0) return true;
    final path = agentExecutable.path;
    final shellCommand =
        "chown root:wheel '${path.replaceAll("'", "'\\''")}' && chmod u+s '${path.replaceAll("'", "'\\''")}'";
    final appleScriptSafeCommand =
        shellCommand.replaceAll('\\', '\\\\').replaceAll('"', '\\"');
    final result = await Process.run('osascript', [
      '-e',
      'do shell script "$appleScriptSafeCommand" with administrator privileges '
          'with prompt "LocalScale precisa de uma permissão única para habilitar a rede privada entre seus dispositivos."',
    ]);
    if (result.exitCode != 0) {
      print('LocalScale: could not grant virtual network privilege: ${result.stderr}');
      return false;
    }
    return true;
  } catch (error) {
    print('LocalScale: virtual network privilege request failed: $error');
    return false;
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
