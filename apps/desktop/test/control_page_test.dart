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
}
