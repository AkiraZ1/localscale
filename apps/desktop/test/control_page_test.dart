import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:localscale_desktop/local_agent_api.dart';
import 'package:localscale_desktop/main.dart';

void main() {
  testWidgets('application starts directly on the control page',
      (tester) async {
    await tester.pumpWidget(
        LocalScaleApp(api: LocalAgentApiClient(FakeLocalAgentTransport())));
    await tester.pump();
    expect(find.text('Control center'), findsOneWidget);
    expect(find.byKey(const Key('login-button')), findsNothing);
  });

  testWidgets('mode selection switches between Cliente and Host',
      (tester) async {
    final transport = FakeLocalAgentTransport();
    await tester.pumpWidget(
        MaterialApp(home: ControlPage(api: LocalAgentApiClient(transport))));
    await tester.pump();
    expect(find.text('Cliente'), findsOneWidget);
    await tester.tap(find.text('Host'));
    await tester.pump();
    expect(transport.current.mode, LocalScaleMode.host);
    expect(find.text('Host'), findsOneWidget);
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
    await tester.tap(find.byTooltip('Refresh'));
    await tester.pumpAndSettle();

    expect(
        find.text('Unable to read LocalScale agent: Bad state: status failed'),
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

  testWidgets('client reviews invitation before agent import and restart',
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
      ..nextStatus = const ServiceStatus(
          mode: LocalScaleMode.host,
          state: ServiceState.running,
          onionEndpoint:
              'abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion');
    await tester.pumpWidget(MaterialApp(home: ControlPage(api: api)));
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
    expect(find.byKey(const Key('activate-invitation')), findsOneWidget);
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
      const NetworkDevicesResponse(
        transport: 'Tor v3 Onion (Strict Isolation)',
        isolation: 'tor_only_no_lan',
        localDevice: NetworkDevice(
          nodeId: 'local-test',
          role: 'cliente',
          onionEndpoint: null,
          virtualIp: '10.42.0.1',
          status: 'active',
          isLocal: true,
        ),
        remotePeers: [
          NetworkDevice(
            nodeId: 'remote-test',
            role: 'host',
            onionEndpoint: 'remote.onion',
            virtualIp: '10.42.0.2',
            status: 'connected',
            isLocal: false,
          ),
        ],
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
