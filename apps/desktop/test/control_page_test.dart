import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:localscale_desktop/local_agent_api.dart';
import 'package:localscale_desktop/main.dart';

void main() {
  testWidgets('application starts signed out on login screen', (tester) async {
    await tester.pumpWidget(
        LocalScaleApp(api: LocalAgentApiClient(FakeLocalAgentTransport())));
    await tester.pump();
    expect(find.byKey(const Key('login-button')), findsOneWidget);
    expect(find.text('Control center'), findsNothing);
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
}

class ControlledApi implements LocalAgentApi {
  int statusCalls = 0;
  bool failStatus = false;
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
}
