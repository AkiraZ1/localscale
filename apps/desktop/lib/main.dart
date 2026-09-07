import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'core/browser_auth/browser_auth.dart';
import 'core/browser_auth/browser_platform.dart';
import 'features/auth/login_controller.dart';
import 'local_agent_api.dart';
import 'local_agent_transport.dart';
import 'pairing_invitation.dart';
import 'test_pairing_bootstrap.dart';

// Native agents keep their installed ports: macOS 18765, other platforms 8765.
final int localAgentPort =
    defaultTargetPlatform == TargetPlatform.macOS ? 18765 : 8765;
const String googleClientId = String.fromEnvironment(
  'LOCALSCALE_GOOGLE_CLIENT_ID',
  defaultValue: 'local-agent',
);

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final agentRunning = await ensureLocalAgentRunning();
  final api = LocalAgentApiClient(defaultLocalAgentTransport());
  if (agentRunning) {
    final platform = defaultTargetPlatform == TargetPlatform.linux
        ? TestPairingPlatform.linux
        : defaultTargetPlatform == TargetPlatform.macOS
            ? TestPairingPlatform.macOS
            : TestPairingPlatform.unsupported;
    try {
      final outcome = await TestPairingBootstrap(api)
          .run(config: TestPairingConfig.fromEnvironment(), platform: platform);
      if (outcome == TestPairingOutcome.restartScheduled) {
        final restarted = await ensureLocalAgentRestarted();
        if (!restarted) {
          debugPrint('LocalScale test pairing could not restart the local '
              'agent after saving the peer profile.');
        } else {
          final resumed = await TestPairingBootstrap(api).run(
              config: TestPairingConfig.fromEnvironment(), platform: platform);
          debugPrint('LocalScale test pairing resumed after agent restart: '
              '$resumed');
        }
      }
    } on Object catch (error) {
      debugPrint('LocalScale test pairing bootstrap failed: $error');
    }
  }
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
        home: ControlPage(api: widget.api, onLogout: () async {}),
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
  final TextEditingController _onionController = TextEditingController();
  final TextEditingController _nodeIdController = TextEditingController();
  final TextEditingController _invitationController = TextEditingController();
  GeneratedInvitation? _generatedInvitation;
  bool _pairingBusy = false;

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
    _onionController.dispose();
    _nodeIdController.dispose();
    _invitationController.dispose();
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
          if (devices?.localDevice.virtualIp != null &&
              _vipController.text.isEmpty) {
            _vipController.text = devices!.localDevice.virtualIp!;
          }
          final onion =
              value.onionEndpoint ?? devices?.localDevice.onionEndpoint;
          if (onion != null &&
              onion.isNotEmpty &&
              _onionController.text != onion) {
            _onionController.text = onion;
          }
          if (_nodeIdController.text.isEmpty && devices != null) {
            _nodeIdController.text = devices.localDevice.nodeId;
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
          SnackBar(
              content: Text('IP Virtual atualizado para $ip (persistido)')),
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

  Future<void> _generateInvitation() async {
    final nodeId = _nodeIdController.text.trim();
    if (nodeId.isEmpty) {
      _pairingMessage('Informe o identificador deste computador.');
      return;
    }
    setState(() => _pairingBusy = true);
    try {
      if (status?.mode != LocalScaleMode.host) {
        await widget.api.setMode(LocalScaleMode.host);
      }
      final generated = await widget.api.generateInvitation(
        nodeId: nodeId,
        virtualIp: _vipController.text.trim(),
      );
      // The agent generated the capability and is the source of truth. Parsing
      // here is only a defensive display check.
      InvitationPreview.parse(generated.invitation);
      if (!mounted) return;
      setState(() {
        _generatedInvitation = generated;
        _invitationController.text = generated.invitation;
      });
      _pairingMessage(
          'Convite criado. Confira, copie e ative o Host para utilizá-lo.');
    } catch (error) {
      _pairingMessage('Não foi possível gerar o convite: $error');
    } finally {
      if (mounted) setState(() => _pairingBusy = false);
    }
  }

  Future<void> _activateGeneratedInvitation() async {
    final generated = _generatedInvitation;
    if (generated == null) return;
    final preview = InvitationPreview.parse(generated.invitation);
    final confirmed = await _confirmInvitation(
      preview,
      title: 'Ativar este Host?',
      explanation:
          'O código abaixo identifica este convite específico; compare-o por um canal confiável com o Cliente.',
    );
    if (confirmed != true || !mounted) return;
    await _approveAndRestart('Host ativado. O agente será reiniciado.');
  }

  Future<void> _importInvitation() async {
    final nodeId = _nodeIdController.text.trim();
    final invitation = _invitationController.text.trim();
    if (nodeId.isEmpty || invitation.isEmpty) {
      _pairingMessage('Informe o identificador local e cole o convite.');
      return;
    }
    InvitationPreview preview;
    try {
      preview = InvitationPreview.parse(invitation);
    } on FormatException catch (error) {
      _pairingMessage(error.message);
      return;
    }
    final confirmed = await _confirmInvitation(
      preview,
      title: 'Confirmar conexão?',
      explanation:
          'Este é apenas um resumo visual. O agente local ainda validará validade, expiração e uso único do convite.',
    );
    if (confirmed != true || !mounted) return;
    setState(() => _pairingBusy = true);
    try {
      if (status?.mode != LocalScaleMode.cliente) {
        await widget.api.setMode(LocalScaleMode.cliente);
      }
      await widget.api.importInvitation(
        nodeId: nodeId,
        invitation: invitation,
        virtualIp: _vipController.text.trim(),
      );
      await widget.api.approvePeer();
      await widget.api.restartRuntime();
      _pairingMessage('Convite aprovado. Aguardando o agente reiniciar…');
      await ensureLocalAgentRestarted();
      if (mounted) _pairingMessage('Agente reiniciado com sucesso.');
    } catch (error) {
      _pairingMessage('Falha ao importar convite: $error');
    } finally {
      if (mounted) setState(() => _pairingBusy = false);
    }
  }

  Future<void> _approveAndRestart(String success) async {
    setState(() => _pairingBusy = true);
    try {
      await widget.api.approvePeer();
      await widget.api.restartRuntime();
      _pairingMessage('Aguardando o agente reiniciar…');
      await ensureLocalAgentRestarted();
      if (mounted) _pairingMessage(success);
    } catch (error) {
      _pairingMessage('Falha ao ativar convite: $error');
    } finally {
      if (mounted) setState(() => _pairingBusy = false);
    }
  }

  Future<bool?> _confirmInvitation(InvitationPreview preview,
      {required String title, required String explanation}) {
    return showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(title),
        content: Column(mainAxisSize: MainAxisSize.min, children: [
          Text(explanation),
          const SizedBox(height: 16),
          SelectableText('Host: ${preview.hostNodeId}'),
          SelectableText('Onion: ${preview.onionEndpoint}'),
          SelectableText('Expira: ${preview.expiresAt.toLocal()}'),
          const SizedBox(height: 12),
          const Text('Código de comparação do convite'),
          SelectableText(preview.fingerprint,
              key: const Key('invitation-fingerprint'),
              style: const TextStyle(fontWeight: FontWeight.bold)),
        ]),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: const Text('Cancelar')),
          FilledButton(
              key: const Key('confirm-invitation'),
              onPressed: () => Navigator.pop(context, true),
              child: const Text('Confirmar')),
        ],
      ),
    );
  }

  void _pairingMessage(String text) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(text)));
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
                                  onSelectionChanged: (s) {
                                    _vipController.clear();
                                    _onionController.clear();
                                    _nodeIdController.clear();
                                    _run(() => widget.api.setMode(s.first),
                                        'Mode update');
                                  }),
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
                              Row(
                                children: [
                                  Expanded(
                                    child: TextField(
                                      controller: _onionController,
                                      readOnly: true,
                                      decoration: InputDecoration(
                                        labelText: 'Onion endpoint (Tor v3)',
                                        hintText: current?.mode ==
                                                LocalScaleMode.host
                                            ? 'Detectando endpoint Onion do Host...'
                                            : 'Disponível no modo Host ou ao parear',
                                        border: const OutlineInputBorder(),
                                      ),
                                    ),
                                  ),
                                  const SizedBox(width: 8),
                                  IconButton.filledTonal(
                                    tooltip: 'Copiar Onion',
                                    onPressed: () {
                                      if (_onionController.text.isNotEmpty) {
                                        Clipboard.setData(ClipboardData(
                                            text: _onionController.text));
                                        ScaffoldMessenger.of(context)
                                            .showSnackBar(
                                          const SnackBar(
                                              content: Text(
                                                  'Endereço .onion copiado!')),
                                        );
                                      }
                                    },
                                    icon: const Icon(Icons.copy),
                                  ),
                                ],
                              ),
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
                        Wrap(
                          alignment: WrapAlignment.spaceBetween,
                          crossAxisAlignment: WrapCrossAlignment.center,
                          spacing: 12,
                          runSpacing: 8,
                          children: [
                            Text('Rede Onion & Dispositivos',
                                style: Theme.of(context).textTheme.titleLarge),
                            Container(
                              padding: const EdgeInsets.symmetric(
                                  horizontal: 8, vertical: 4),
                              decoration: BoxDecoration(
                                color: Colors.green.withValues(alpha: 0.15),
                                borderRadius: BorderRadius.circular(6),
                              ),
                              child: const Row(
                                mainAxisSize: MainAxisSize.min,
                                children: [
                                  Icon(Icons.shield,
                                      size: 14, color: Colors.green),
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
                            ...devices.remotePeers.map((peer) =>
                                _buildDeviceTile(peer, isLocal: false)),
                        ] else ...[
                          const Text('Carregando dispositivos da rede Onion...',
                              style: TextStyle(color: Colors.grey)),
                        ],
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 16),
                _buildInvitationCard(current),
              ]))),
    );
  }

  Widget _buildInvitationCard(ServiceStatus? current) {
    final isHost = current?.mode == LocalScaleMode.host;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('Pareamento por convite',
              style: Theme.of(context).textTheme.titleLarge),
          const SizedBox(height: 8),
          Text(isHost
              ? 'Gere um convite de uso único e envie-o ao Cliente por um canal confiável.'
              : 'Cole o convite recebido do Host, confira os dados e aprove localmente.'),
          const SizedBox(height: 12),
          TextField(
            key: const Key('pairing-node-id'),
            controller: _nodeIdController,
            decoration: const InputDecoration(
                labelText: 'Identificador deste computador',
                border: OutlineInputBorder()),
          ),
          const SizedBox(height: 12),
          TextField(
            key: const Key('pairing-invitation'),
            controller: _invitationController,
            minLines: 2,
            maxLines: 4,
            readOnly: isHost && _generatedInvitation != null,
            decoration: InputDecoration(
                labelText: isHost ? 'Convite gerado' : 'Convite do Host',
                hintText: 'lsinv1.…',
                border: const OutlineInputBorder(),
                suffixIcon: IconButton(
                  tooltip: 'Copiar convite',
                  onPressed: _invitationController.text.trim().isEmpty
                      ? null
                      : () {
                          Clipboard.setData(ClipboardData(
                              text: _invitationController.text.trim()));
                          _pairingMessage('Convite copiado.');
                        },
                  icon: const Icon(Icons.copy),
                )),
          ),
          const SizedBox(height: 12),
          Wrap(spacing: 8, runSpacing: 8, children: [
            if (isHost)
              FilledButton.icon(
                  key: const Key('generate-invitation'),
                  onPressed: _pairingBusy ? null : _generateInvitation,
                  icon: const Icon(Icons.add_link),
                  label: const Text('Gerar convite'))
            else
              FilledButton.icon(
                  key: const Key('import-invitation'),
                  onPressed: _pairingBusy ? null : _importInvitation,
                  icon: const Icon(Icons.link),
                  label: const Text('Revisar e conectar')),
            if (isHost && _generatedInvitation != null)
              OutlinedButton.icon(
                  key: const Key('activate-invitation'),
                  onPressed: _pairingBusy ? null : _activateGeneratedInvitation,
                  icon: const Icon(Icons.verified_user),
                  label: const Text('Ativar Host')),
          ]),
          if (_generatedInvitation != null && isHost) ...[
            const SizedBox(height: 8),
            Text(
                'Expira em ${_generatedInvitation!.expiresAt.toLocal()}. Gerar outro convite invalida a configuração pendente anterior.'),
          ],
          const SizedBox(height: 8),
          const Text(
            'A conta Google autoriza somente o painel local. O convite é a credencial de pareamento; não é sincronizado pelo Google e deve permanecer privado.',
            style: TextStyle(fontSize: 12, color: Colors.grey),
          ),
        ]),
      ),
    );
  }

  Widget _buildDeviceTile(NetworkDevice dev, {required bool isLocal}) {
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Theme.of(context)
            .colorScheme
            .surfaceContainerHighest
            .withValues(alpha: 0.4),
        border: Border.all(color: Colors.white10),
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
                      padding: const EdgeInsets.symmetric(
                          horizontal: 6, vertical: 2),
                      decoration: BoxDecoration(
                        color: Colors.blue.withValues(alpha: 0.2),
                        borderRadius: BorderRadius.circular(4),
                      ),
                      child: Text(
                        dev.role.toUpperCase(),
                        style: const TextStyle(
                            fontSize: 10, color: Colors.blueAccent),
                      ),
                    ),
                    if (isLocal) ...[
                      const SizedBox(width: 6),
                      Container(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 6, vertical: 2),
                        decoration: BoxDecoration(
                          color: Colors.green.withValues(alpha: 0.2),
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
                  'IP Virtual: ${dev.virtualIp?.isNotEmpty == true ? dev.virtualIp : "não configurado"} | Onion: ${dev.onionEndpoint?.isNotEmpty == true ? dev.onionEndpoint : (isLocal ? "aguardando Tor" : "não configurado")}',
                  style: const TextStyle(fontSize: 12, color: Colors.grey),
                ),
              ],
            ),
          ),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
            decoration: BoxDecoration(
              color: dev.status == 'active' ||
                      dev.status == 'connected'
                  ? Colors.green.withValues(alpha: 0.15)
                  : Colors.orange.withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Text(
              dev.status,
              style: TextStyle(
                fontSize: 11,
                color: dev.status == 'active' ||
                        dev.status == 'connected'
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
