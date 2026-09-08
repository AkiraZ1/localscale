import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:localscale_desktop/local_agent_api.dart';
import 'package:localscale_desktop/main.dart';

void main() {
  testWidgets(
      'application starts directly on the setup wizard, no login screen',
      (tester) async {
    await tester.pumpWidget(LocalScaleApp(
        api: LocalAgentApiClient(
            FakeLocalAgentTransport(includeRemotePeer: false))));
    await tester.pump();
    expect(find.byKey(const Key('login-button')), findsNothing);
    expect(find.text('Criar uma rede nova'), findsOneWidget);
  });

  testWidgets('choosing a role sets the agent mode and advances the wizard',
      (tester) async {
    final transport = FakeLocalAgentTransport(includeRemotePeer: false);
    await tester.pumpWidget(
        MaterialApp(home: ControlPage(api: LocalAgentApiClient(transport))));
    await tester.pump();
    expect(find.text('Criar uma rede nova'), findsOneWidget);
    await tester.tap(find.text('Criar uma rede nova'));
    await tester.pump();
    expect(transport.current.mode, LocalScaleMode.host);
    expect(find.byKey(const Key('pairing-node-id')), findsOneWidget);
  });

  testWidgets('polling refreshes status while the page is mounted',
      (tester) async {
    final api = ControlledApi();
    await tester.pumpWidget(MaterialApp(home: ControlPage(api: api)));
    await tester.pump();
    api.nextStatus = const ServiceStatus(
        mode: LocalScaleMode.cliente, state: ServiceState.running);

    await tester.pump(const Duration(seconds: 5));
    await tester.pump();

    expect(api.statusCalls, greaterThanOrEqualTo(2));
    expect(find.text('Running'), findsOneWidget);
  });

  testWidgets('polling stops when the page is disposed', (tester) async {
    final api = ControlledApi();
    await tester.pumpWidget(MaterialApp(home: ControlPage(api: api)));
    await tester.pump();
    final callsBeforeDispose = api.statusCalls;

    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pump(const Duration(seconds: 15));

    expect(api.statusCalls, callsBeforeDispose);
  });

  testWidgets('refresh failure clears the displayed status', (tester) async {
    final api = ControlledApi();
    await tester.pumpWidget(MaterialApp(home: ControlPage(api: api)));
    await tester.pump();
    expect(find.text('Stopped'), findsOneWidget);

    api.failStatus = true;
    await tester.tap(find.byTooltip('Atualizar'));
    await tester.pumpAndSettle();

    expect(
        find.text(
            'Não foi possível conectar ao serviço local. Tentando novamente…'),
        findsOneWidget);
    expect(find.text('Stopped'), findsNothing);
  });

  testWidgets('displays Onion network card, virtual IP, and devices',
      (tester) async {
    tester.view.physicalSize = const Size(1200, 1600);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    final api = ControlledApi();
    await tester.pumpWidget(MaterialApp(home: ControlPage(api: api)));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 100));
    expect(find.text('Sua Rede & Dispositivos'), findsOneWidget);
    expect(find.text('Conexão 100% criptografada'), findsOneWidget);
    expect(find.text('local-test'), findsAtLeastNWidgets(1));
    expect(find.text('remote-test'), findsOneWidget);
    expect(find.text('ESTE COMPUTADOR'), findsOneWidget);
  });

  testWidgets(
      'dashboard lets a Host add another device without restarting existing peers',
      (tester) async {
    tester.view.physicalSize = const Size(1200, 1800);
    tester.view.devicePixelRatio = 1;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });
    final api = ControlledApi()
      ..nextStatus = const ServiceStatus(
          mode: LocalScaleMode.host, state: ServiceState.running);
    await tester.pumpWidget(MaterialApp(home: ControlPage(api: api)));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 100));

    expect(find.text('Sua Rede & Dispositivos'), findsOneWidget);
    expect(find.byKey(const Key('add-device')), findsOneWidget);

    await tester.ensureVisible(find.byKey(const Key('add-device')));
    await tester.tap(find.byKey(const Key('add-device')));
    await tester.pump();

    // Back in the wizard at the invitation step, not the dashboard, and a
    // "Cancelar" escape hatch back to the dashboard is visible.
    expect(find.byKey(const Key('generate-invitation')), findsOneWidget);
    expect(find.byKey(const Key('wizard-cancel-to-dashboard')), findsOneWidget);

    await tester.ensureVisible(find.byKey(const Key('generate-invitation')));
    await tester.tap(find.byKey(const Key('generate-invitation')));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 50));

    // Adding a device while already paired must NOT trigger the
    // first-time-setup restart, or every other connected Cliente would be
    // disconnected for no reason.
    expect(api.generateCalls, 1);
    expect(api.restartCalls, 0);

    await tester.tap(find.byKey(const Key('wizard-cancel-to-dashboard')));
    await tester.pump();
    expect(find.text('Sua Rede & Dispositivos'), findsOneWidget);
  });

  testWidgets('dashboard "Mudar modo" re-enters the wizard at the role step',
      (tester) async {
    tester.view.physicalSize = const Size(1200, 1800);
    tester.view.devicePixelRatio = 1;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });
    final api = ControlledApi();
    await tester.pumpWidget(MaterialApp(home: ControlPage(api: api)));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 100));

    await tester.ensureVisible(find.byKey(const Key('change-mode')));
    await tester.tap(find.byKey(const Key('change-mode')));
    await tester.pump();

    expect(find.text('Criar uma rede nova'), findsOneWidget);
    expect(find.byKey(const Key('wizard-cancel-to-dashboard')), findsOneWidget);
  });

  testWidgets('Host can remove one specific connected device',
      (tester) async {
    tester.view.physicalSize = const Size(1200, 1800);
    tester.view.devicePixelRatio = 1;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });
    final api = ControlledApi()
      ..nextStatus = const ServiceStatus(
          mode: LocalScaleMode.host, state: ServiceState.running);
    await tester.pumpWidget(MaterialApp(home: ControlPage(api: api)));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 100));

    await tester.ensureVisible(find.byKey(const Key('remove-device-tile')));
    await tester.tap(find.byKey(const Key('remove-device-tile')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Remover'));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 50));

    expect(api.removedHostPeerNodeIds, ['remote-test']);
    // A Host removing one device must use the multi-peer endpoint, never
    // the Cliente-only single-pairing reset.
    expect(api.resetCalls, 0);
  });

  testWidgets('client reviews invitation before agent import and restart',
      (tester) async {
    tester.view.physicalSize = const Size(1200, 1800);
    tester.view.devicePixelRatio = 1;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });
    final api = ControlledApi()..includeRemotePeer = false;
    await tester.pumpWidget(MaterialApp(home: ControlPage(api: api)));
    await tester.pump();
    // Role page first: this device is joining an existing network.
    await tester.tap(find.text('Entrar em uma rede existente'));
    await tester.pump();
    // Name page: choosing a role clears the name field (it's a fresh setup
    // decision each time), so it must be filled in before continuing.
    await tester.enterText(
        find.byKey(const Key('pairing-node-id')), 'cliente-test-node');
    await tester.pump();
    await tester.ensureVisible(
        find.byKey(const Key('wizard-step-name-continue')).first);
    await tester
        .tap(find.byKey(const Key('wizard-step-name-continue')).first);
    await tester.pump();
    await tester
        .ensureVisible(find.byKey(const Key('pairing-invitation')).first);
    final payload = base64Url
        .encode(utf8.encode(jsonEncode({
          'version': 1,
          'invitation_id': 'id',
          'host_node_id': 'linux-host',
          'onion_endpoint':
              'abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion',
          'invitation_secret': 'secret',
          'issued_at': 1700000000,
          'expires_at': 4102444800,
        })))
        .replaceAll('=', '');
    await tester.enterText(
        find.byKey(const Key('pairing-invitation')).first, 'lsinv1.$payload');
    await tester.tap(find.byKey(const Key('import-invitation')));
    await tester.pump();

    expect(find.text('Confirmar conexão?'), findsOneWidget);
    expect(find.text('Host: linux-host'), findsOneWidget);
    expect(find.byKey(const Key('invitation-fingerprint')), findsOneWidget);
    expect(api.importCalls, 0);

    await tester.tap(find.byKey(const Key('confirm-invitation')));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 50));
    expect(api.importCalls, 1);
    expect(api.approveCalls, 1);
    expect(api.restartCalls, 1);
    // _importInvitation awaits the real ensureLocalAgentRestarted(), which
    // retries against a real (in this test environment, always-failing)
    // HTTP probe for several seconds before giving up — drain that fully so
    // no timer is left pending when the test ends.
    await tester.pump(const Duration(seconds: 20));
  });

  testWidgets('host generates an invitation and auto-activates it',
      (tester) async {
    tester.view.physicalSize = const Size(1200, 1800);
    tester.view.devicePixelRatio = 1;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });
    final api = ControlledApi()
      ..includeRemotePeer = false
      ..nextStatus = const ServiceStatus(
          mode: LocalScaleMode.host,
          state: ServiceState.running,
          onionEndpoint:
              'abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion');
    await tester.pumpWidget(MaterialApp(home: ControlPage(api: api)));
    await tester.pump();
    // Role page first: this device is creating the network.
    await tester.tap(find.text('Criar uma rede nova'));
    await tester.pump();
    // Name page: choosing a role clears the name field (it's a fresh setup
    // decision each time), so it must be filled in before continuing.
    await tester.enterText(
        find.byKey(const Key('pairing-node-id')), 'host-test-node');
    await tester.pump();
    await tester
        .ensureVisible(find.byKey(const Key('wizard-step-name-continue')));
    await tester.tap(find.byKey(const Key('wizard-step-name-continue')));
    await tester.pump();
    await tester.ensureVisible(find.byKey(const Key('generate-invitation')));
    await tester.tap(find.byKey(const Key('generate-invitation')));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 50));

    expect(api.generateCalls, 1);
    // Generating an invitation already expresses intent to accept a peer,
    // so _generateInvitation auto-activates (calls _approveAndRestart) —
    // no separate manual step is needed, which is the whole point: one
    // action, not two.
    expect(api.approveCalls, 1);
    expect(api.restartCalls, 1);
    // Activation is automatic now — there is no separate "Ativar" step to
    // find or tap; a Cliente can already complete pairing the instant the
    // invitation is generated.
    // _approveAndRestart awaits the real ensureLocalAgentRestarted() —
    // several seconds of retries against an always-failing HTTP probe in
    // this test environment — drain it so no timer is left pending.
    await tester.pump(const Duration(seconds: 20));
  });
}

class ControlledApi implements LocalAgentApi {
  int statusCalls = 0;
  bool failStatus = false;
  int importCalls = 0;
  int approveCalls = 0;
  int restartCalls = 0;
  int generateCalls = 0;
  bool includeRemotePeer = true;
  ServiceStatus nextStatus = const ServiceStatus(
      mode: LocalScaleMode.cliente, state: ServiceState.stopped);

  @override
  Future<ServiceStatus> status() async {
    statusCalls++;
    if (failStatus) {
      throw StateError('status failed');
    }
    return nextStatus;
  }

  @override
  Future<ServiceStatus> setMode(LocalScaleMode mode) =>
      Future.value(nextStatus);

  @override
  Future<ServiceStatus> start() => Future.value(nextStatus);

  @override
  Future<ServiceStatus> stop() => Future.value(nextStatus);

  @override
  Future<ServiceStatus> sync() => Future.value(nextStatus);

  @override
  Future<PeerStatus> peerStatus() => Future.value(const PeerStatus(
      configured: false,
      transport: 'unavailable',
      connected: false,
      approved: false));

  @override
  Future<PeerStatus> approvePeer() {
    approveCalls++;
    return Future.value(const PeerStatus(
        configured: true,
        transport: 'restart_required',
        connected: false,
        approved: true));
  }

  @override
  Future<GeneratedInvitation> generateInvitation(
      {required String nodeId,
      String? virtualIp,
      Duration ttl = const Duration(minutes: 10)}) async {
    generateCalls++;
    final payload = base64Url
        .encode(utf8.encode(jsonEncode({
          'version': 1,
          'invitation_id': 'id',
          'host_node_id': nodeId,
          'onion_endpoint':
              'abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion',
          'invitation_secret': 'secret',
          'issued_at': 1700000000,
          'expires_at': 4102444800,
        })))
        .replaceAll('=', '');
    return GeneratedInvitation(
        version: 1,
        invitation: 'lsinv1.$payload',
        expiresAt:
            DateTime.fromMillisecondsSinceEpoch(4102444800000, isUtc: true));
  }

  @override
  Future<PeerStatus> importInvitation(
      {required String nodeId,
      required String invitation,
      String? virtualIp}) async {
    importCalls++;
    return const PeerStatus(
        configured: true,
        transport: 'restart_required',
        connected: false,
        approved: false);
  }

  @override
  Future<void> restartRuntime() async {
    restartCalls++;
  }

  @override
  Future<NetworkDevicesResponse> getDevices() async =>
      NetworkDevicesResponse(
        transport: 'Tor v3 Onion (Strict Isolation)',
        isolation: 'tor_only_no_lan',
        localDevice: const NetworkDevice(
          nodeId: 'local-test',
          role: 'cliente',
          onionEndpoint: null,
          virtualIp: '10.42.0.1',
          status: 'active',
          isLocal: true,
        ),
        remotePeers: includeRemotePeer
            ? const [
                NetworkDevice(
                  nodeId: 'remote-test',
                  role: 'host',
                  onionEndpoint: 'remote.onion',
                  virtualIp: '10.42.0.2',
                  status: 'connected',
                  isLocal: false,
                ),
              ]
            : const [],
      );

  @override
  Future<void> setVirtualIp(String virtualIp) async {}

  int resetCalls = 0;

  @override
  Future<PeerStatus> resetPeer() {
    resetCalls++;
    return Future.value(const PeerStatus(
        configured: false,
        transport: 'unavailable',
        connected: false,
        approved: false));
  }

  final List<String> removedHostPeerNodeIds = [];

  @override
  Future<void> removeHostPeer(String nodeId) async {
    removedHostPeerNodeIds.add(nodeId);
  }

  @override
  Future<PeerStatus> setPeerConfig({
    required String role,
    required String nodeId,
    required String onionEndpoint,
    String? hostNodeId,
    required String invitationSecret,
    String? virtualIp,
  }) async =>
      const PeerStatus(
          configured: true,
          transport: 'unavailable',
          connected: false,
          approved: false);

  @override
  Future<String> backendLogTail() async => '';
}
