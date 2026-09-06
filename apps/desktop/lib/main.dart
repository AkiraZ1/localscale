import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'core/browser_auth/browser_auth.dart';
import 'core/browser_auth/browser_platform.dart';
import 'features/auth/login_controller.dart';
import 'local_agent_api.dart';
import 'local_agent_transport.dart';

// Native agents keep their installed ports: macOS 18765, other platforms 8765.
final int localAgentPort =
    defaultTargetPlatform == TargetPlatform.macOS ? 18765 : 8765;
const String googleClientId = String.fromEnvironment(
  'LOCALSCALE_GOOGLE_CLIENT_ID',
  defaultValue: 'local-agent',
);

void main() {
  final api = LocalAgentApiClient(defaultLocalAgentTransport());
  final auth = LoginController(
    oauth: BrowserOAuthClient(
      request: OAuthAuthorizationRequest(
        authorizationEndpoint: Uri(
            scheme: 'http',
            host: '127.0.0.1',
            port: localAgentPort,
            path: '/oauth/google/start'),
        clientId: googleClientId,
        redirectUri: Uri(
            scheme: 'http',
            host: '127.0.0.1',
            port: localAgentPort,
            path: '/oauth/google/callback'),
        scopes: <String>['openid', 'email', 'profile'],
      ),
      browserLauncher: systemBrowserLauncher(),
      callbackReceiver: loopbackCallbackReceiver(),
      exchanger: localSessionBridge(
          Uri(scheme: 'http', host: '127.0.0.1', port: localAgentPort)),
    ),
    storage: MemorySessionStorage(),
  );
  runApp(LocalScaleApp(api: api, auth: auth));
}

class MemorySessionStorage implements SecureSessionStorage {
  SecureSession? _session;
  @override
  Future<SecureSession?> read() async => _session;
  @override
  Future<void> write(SecureSession session) async => _session = session;
  @override
  Future<void> clear() async => _session = null;
}

class LocalScaleApp extends StatefulWidget {
  const LocalScaleApp({super.key, required this.api, this.auth});
  final LocalAgentApi api;
  final LoginController? auth;
  @override
  State<LocalScaleApp> createState() => _LocalScaleAppState();
}

class _LocalScaleAppState extends State<LocalScaleApp> {
  late final LoginController auth;
  @override
  void initState() {
    super.initState();
    auth = widget.auth ?? _unconfiguredAuth();
    auth.restoreSession();
  }

  LoginController _unconfiguredAuth() => LoginController(
      oauth: _UnavailableOAuth(), storage: MemorySessionStorage());
  @override
  void dispose() {
    auth.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'LocalScale',
        theme: ThemeData(
            colorScheme:
                ColorScheme.fromSeed(seedColor: const Color(0xff6750a4)),
            useMaterial3: true),
        home: AnimatedBuilder(
            animation: auth,
            builder: (_, __) => auth.model.state == AuthState.signedIn
                ? ControlPage(api: widget.api, onLogout: auth.logout)
                : LoginPage(controller: auth)),
      );
}

class _UnavailableOAuth implements BrowserOAuthClient {
  @override
  noSuchMethod(Invocation invocation) => throw const AuthException(
      AuthErrorCode.exchangeFailed, 'Authentication is unavailable');
}

class LoginPage extends StatelessWidget {
  const LoginPage({super.key, required this.controller});
  final LoginController controller;
  @override
  Widget build(BuildContext context) => Scaffold(
        body: Center(
            child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 420),
                child: Card(
                  child: Padding(
                      padding: const EdgeInsets.all(28),
                      child: Column(mainAxisSize: MainAxisSize.min, children: [
                        Text('LocalScale',
                            style: Theme.of(context).textTheme.headlineMedium),
                        const SizedBox(height: 12),
                        const Text('Sign in to manage this local agent.'),
                        const SizedBox(height: 24),
                        FilledButton.icon(
                            key: const Key('login-button'),
                            onPressed: controller.model.canLogin
                                ? controller.login
                                : null,
                            icon: const Icon(Icons.login),
                            label: Text(
                                controller.model.state == AuthState.authorizing
                                    ? 'Opening browser…'
                                    : 'Sign in with Google')),
                        if (controller.model.error != null) ...[
                          const SizedBox(height: 16),
                          Text(controller.model.error!.message,
                              key: const Key('auth-error'))
                        ],
                        if (kIsWeb) ...[
                          const SizedBox(height: 16),
                          const Text(
                              'Desktop sign-in is required; Web authentication is disabled.')
                        ],
                      ])),
                ))),
      );
}

class ControlPage extends StatefulWidget {
  const ControlPage({super.key, required this.api, this.onLogout});
  final LocalAgentApi api;
  final Future<void> Function()? onLogout;
  @override
  State<ControlPage> createState() => _ControlPageState();
}

class _ControlPageState extends State<ControlPage> {
  static const _pollInterval = Duration(seconds: 5);
  ServiceStatus? status;
  String? message;
  Timer? _pollTimer;
  @override
  void initState() {
    super.initState();
    _refresh();
    _pollTimer = Timer.periodic(_pollInterval, (_) {
      if (mounted) _refresh();
    });
  }

  @override
  void dispose() {
    _pollTimer?.cancel();
    super.dispose();
  }

  Future<void> _refresh() async {
    try {
      final value = await widget.api.status();
      if (mounted) {
        setState(() {
          status = value;
          message = null;
        });
      }
    } catch (error) {
      if (mounted) {
        setState(() {
          status = null;
          message = 'Unable to read LocalScale agent: $error';
        });
      }
    }
  }

  Future<void> _run(
      Future<ServiceStatus> Function() action, String label) async {
    if (!mounted) return;
    setState(() => message = '$label LocalScale…');
    try {
      final value = await action();
      if (mounted) {
        setState(() {
          status = value;
          message = '$label complete';
        });
      }
    } catch (error) {
      if (mounted) setState(() => message = '$label failed: $error');
    }
  }

  @override
  Widget build(BuildContext context) {
    final current = status;
    return Scaffold(
      appBar: AppBar(title: const Text('LocalScale'), actions: [
        IconButton(
            onPressed: _refresh,
            icon: const Icon(Icons.refresh),
            tooltip: 'Refresh'),
        if (widget.onLogout != null)
          IconButton(
              onPressed: widget.onLogout,
              icon: const Icon(Icons.logout),
              tooltip: 'Sign out'),
      ]),
      body: Center(
          child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 900),
              child: ListView(padding: const EdgeInsets.all(24), children: [
                Text('Control center',
                    style: Theme.of(context).textTheme.headlineMedium),
                const SizedBox(height: 8),
                const Text('Manage the local LocalScale service.'),
                const SizedBox(height: 24),
                Card(
                    child: Padding(
                        padding: const EdgeInsets.all(20),
                        child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text('Mode',
                                  style:
                                      Theme.of(context).textTheme.titleLarge),
                              const SizedBox(height: 12),
                              SegmentedButton<LocalScaleMode>(
                                  segments: const [
                                    ButtonSegment(
                                        value: LocalScaleMode.host,
                                        label: Text('Host'),
                                        icon: Icon(Icons.hub)),
                                    ButtonSegment(
                                        value: LocalScaleMode.cliente,
                                        label: Text('Cliente'),
                                        icon: Icon(Icons.devices))
                                  ],
                                  selected: {
                                    current?.mode ?? LocalScaleMode.cliente
                                  },
                                  onSelectionChanged: (s) => _run(
                                      () => widget.api.setMode(s.first),
                                      'Mode update')),
                              const SizedBox(height: 8),
                              const Text(
                                  'Host publishes an Onion service. Cliente connects outbound.'),
                            ]))),
                const SizedBox(height: 16),
                Card(
                    child: Padding(
                        padding: const EdgeInsets.all(20),
                        child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text('Service status',
                                  style:
                                      Theme.of(context).textTheme.titleLarge),
                              const SizedBox(height: 12),
                              Row(children: [
                                Icon(Icons.circle,
                                    size: 14,
                                    color: _stateColor(current?.state)),
                                const SizedBox(width: 8),
                                Text(_stateLabel(current?.state))
                              ]),
                              const SizedBox(height: 16),
                              TextFormField(
                                  initialValue: current?.onionEndpoint ?? '',
                                  readOnly: true,
                                  decoration: const InputDecoration(
                                      labelText: 'Onion endpoint',
                                      hintText:
                                          'Available when running as Host',
                                      border: OutlineInputBorder())),
                              const SizedBox(height: 16),
                              Wrap(spacing: 12, runSpacing: 8, children: [
                                FilledButton.icon(
                                    onPressed: () =>
                                        _run(widget.api.start, 'Start'),
                                    icon: const Icon(Icons.play_arrow),
                                    label: const Text('Start')),
                                OutlinedButton.icon(
                                    onPressed: () =>
                                        _run(widget.api.stop, 'Stop'),
                                    icon: const Icon(Icons.stop),
                                    label: const Text('Stop')),
                                OutlinedButton.icon(
                                    onPressed: () =>
                                        _run(widget.api.sync, 'Sync'),
                                    icon: const Icon(Icons.sync),
                                    label: const Text('Sync'))
                              ]),
                              if (message != null) ...[
                                const SizedBox(height: 12),
                                Text(message!, key: const Key('status-message'))
                              ],
                            ]))),
              ]))),
    );
  }

  Color _stateColor(ServiceState? state) => switch (state) {
        ServiceState.running => Colors.green,
        null => Colors.grey,
        _ => Colors.orange,
      };

  String _stateLabel(ServiceState? state) => switch (state) {
        ServiceState.running => 'Running',
        ServiceState.starting => 'Starting',
        ServiceState.stopping => 'Stopping',
        ServiceState.error => 'Error',
        ServiceState.stopped => 'Stopped',
        null => 'Status unavailable',
      };
}
