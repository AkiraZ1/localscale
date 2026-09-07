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
        themeMode: ThemeMode.system,
        theme: ThemeData(
          colorScheme: ColorScheme.fromSeed(
            seedColor: const Color(0xff2563eb),
            brightness: Brightness.light,
          ),
          useMaterial3: true,
        ),
        darkTheme: ThemeData(
          colorScheme: ColorScheme.fromSeed(
            seedColor: const Color(0xff3b82f6),
            brightness: Brightness.dark,
          ),
          useMaterial3: true,
          scaffoldBackgroundColor: const Color(0xff0b0f19),
        ),
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
  NetworkDevicesResponse? networkDevices;
  String? message;
  Timer? _pollTimer;
  final TextEditingController _vipController = TextEditingController();

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
    _vipController.dispose();
    super.dispose();
  }

  Future<void> _refresh() async {
    try {
      final value = await widget.api.status();
      NetworkDevicesResponse? devices;
      try {
        devices = await widget.api.getDevices();
      } catch (_) {}

      if (mounted) {
        setState(() {
          status = value;
          networkDevices = devices;
          if (devices?.localDevice.virtualIp != null && _vipController.text.isEmpty) {
            _vipController.text = devices!.localDevice.virtualIp!;
          }
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

  Future<void> _updateVirtualIp() async {
    final ip = _vipController.text.trim();
    if (ip.isEmpty) return;
    try {
      await widget.api.setVirtualIp(ip);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('IP Virtual atualizado para $ip (persistido)')),
        );
        _refresh();
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Falha ao atualizar IP: $e')),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final current = status;
    final devices = networkDevices;

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
                const SizedBox(height: 16),
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(20),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          mainAxisAlignment: MainAxisAlignment.spaceBetween,
                          children: [
                            Text('Rede Onion & Dispositivos',
                                style: Theme.of(context).textTheme.titleLarge),
                            Container(
                              padding: const EdgeInsets.symmetric(
                                  horizontal: 8, vertical: 4),
                              decoration: BoxDecoration(
                                color: Colors.green.withOpacity(0.15),
                                borderRadius: BorderRadius.circular(6),
                              ),
                              child: const Row(
                                children: [
                                  Icon(Icons.shield, size: 14, color: Colors.green),
                                  SizedBox(width: 4),
                                  Text('Isolamento LAN Ativo (Tor 100%)',
                                      style: TextStyle(
                                          color: Colors.green,
                                          fontSize: 12,
                                          fontWeight: FontWeight.w600)),
                                ],
                              ),
                            ),
                          ],
                        ),
                        const SizedBox(height: 8),
                        const Text(
                          'Todo o tráfego dos nós é estritamente roteado via túnel Onion Tor v3 P2P. Nenhuma porta física é aberta na rede local.',
                          style: TextStyle(color: Colors.grey, fontSize: 13),
                        ),
                        const SizedBox(height: 16),
                        Row(
                          children: [
                            Expanded(
                              child: TextField(
                                controller: _vipController,
                                decoration: const InputDecoration(
                                  labelText: 'IP Virtual Local (Overlay Mesh)',
                                  hintText: 'Ex: 10.42.0.1',
                                  border: OutlineInputBorder(),
                                  isDense: true,
                                ),
                              ),
                            ),
                            const SizedBox(width: 12),
                            FilledButton.tonalIcon(
                              onPressed: _updateVirtualIp,
                              icon: const Icon(Icons.save),
                              label: const Text('Salvar IP'),
                            ),
                          ],
                        ),
                        const SizedBox(height: 20),
                        Text('Dispositivos Conectados:',
                            style: Theme.of(context).textTheme.titleMedium),
                        const SizedBox(height: 10),
                        if (devices != null) ...[
                          _buildDeviceTile(devices.localDevice, isLocal: true),
                          if (devices.remotePeers.isEmpty)
                            const Padding(
                              padding: EdgeInsets.symmetric(vertical: 8),
                              child: Text(
                                'Nenhum outro peer remoto conectado ainda.',
                                style: TextStyle(
                                    color: Colors.grey,
                                    fontStyle: FontStyle.italic),
                              ),
                            )
                          else
                            ...devices.remotePeers
                                .map((peer) => _buildDeviceTile(peer, isLocal: false)),
                        ] else ...[
                          const Text('Carregando dispositivos da rede Onion...',
                              style: TextStyle(color: Colors.grey)),
                        ],
                      ],
                    ),
                  ),
                ),
              ]))),
    );
  }

  Widget _buildDeviceTile(NetworkDevice dev, {required bool isLocal}) {
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surfaceContainerHighest.withOpacity(0.4),
        border: Border.padLeft == null ? Border.all(color: Colors.white10) : null,
        borderRadius: BorderRadius.circular(8),
      ),
      child: Row(
        children: [
          Icon(
            isLocal ? Icons.laptop_mac : Icons.dns,
            color: isLocal ? Colors.blue : Colors.purpleAccent,
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Text(
                      dev.nodeId,
                      style: const TextStyle(fontWeight: FontWeight.bold),
                    ),
                    const SizedBox(width: 8),
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                      decoration: BoxDecoration(
                        color: Colors.blue.withOpacity(0.2),
                        borderRadius: BorderRadius.circular(4),
                      ),
                      child: Text(
                        dev.role.toUpperCase(),
                        style: const TextStyle(fontSize: 10, color: Colors.blueAccent),
                      ),
                    ),
                    if (isLocal) ...[
                      const SizedBox(width: 6),
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                        decoration: BoxDecoration(
                          color: Colors.green.withOpacity(0.2),
                          borderRadius: BorderRadius.circular(4),
                        ),
                        child: const Text(
                          'ESTE COMPUTADOR',
                          style: TextStyle(fontSize: 10, color: Colors.green),
                        ),
                      ),
                    ],
                  ],
                ),
                const SizedBox(height: 4),
                Text(
                  'IP Virtual: ${dev.virtualIp ?? "não configurado"} | Onion: ${dev.onionEndpoint ?? "aguardando"}',
                  style: const TextStyle(fontSize: 12, color: Colors.grey),
                ),
              ],
            ),
          ),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
            decoration: BoxDecoration(
              color: dev.status == 'active' || dev.status == 'approved' || dev.status == 'connected'
                  ? Colors.green.withOpacity(0.15)
                  : Colors.orange.withOpacity(0.15),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Text(
              dev.status,
              style: TextStyle(
                fontSize: 11,
                color: dev.status == 'active' || dev.status == 'approved' || dev.status == 'connected'
                    ? Colors.green
                    : Colors.orange,
              ),
            ),
          ),
        ],
      ),
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
