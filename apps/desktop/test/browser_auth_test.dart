import 'package:flutter_test/flutter_test.dart';

import 'package:localscale_desktop/core/browser_auth/browser_auth.dart';
import 'package:localscale_desktop/features/auth/login_controller.dart';

class RecordingLauncher implements BrowserLauncher {
  Uri? launched;
  @override
  Future<void> launch(Uri url) async => launched = url;
}

class CallbackQueue implements AuthCallbackReceiver {
  CallbackQueue(this.value);
  final Uri? value;
  @override
  Future<Uri?> waitForCallback() async => value;
}

class DynamicCallbackQueue implements DynamicAuthCallbackReceiver {
  DynamicCallbackQueue(this.callback, this.value);
  final Uri callback;
  final Uri value;
  @override
  Future<Uri?> waitForCallback() async => callback;
  @override
  Future<Uri> callbackUri() async => value;
}

class TestPkce implements PkceGenerator {
  @override
  String verifier() => 'verifier';
  @override
  String challenge(String verifier) => 'challenge';
}

class TestExchanger implements AuthorizationCodeExchanger {
  String? handoff;
  String? verifier;
  Uri? callbackUri;
  String? state;
  Object? failure;
  @override
  Future<SecureSession> exchange(
      {required String handoff,
      required String verifier,
      required Uri callbackUri,
      required String state}) async {
    if (failure != null) throw failure!;
    this.handoff = handoff;
    this.verifier = verifier;
    this.callbackUri = callbackUri;
    this.state = state;
    return SecureSession(
        sessionId: 'opaque-session', expiresAt: DateTime(2030));
  }
}

class MemoryStorage implements SecureSessionStorage {
  SecureSession? value;
  int clears = 0;
  @override
  Future<SecureSession?> read() async => value;
  @override
  Future<void> write(SecureSession session) async => value = session;
  @override
  Future<void> clear() async {
    value = null;
    clears++;
  }
}

BrowserOAuthClient client(
    {required Uri? callback,
    RecordingLauncher? launcher,
    TestExchanger? exchanger}) {
  return BrowserOAuthClient(
    request: OAuthAuthorizationRequest(
      authorizationEndpoint:
          Uri.parse('https://broker.invalid/authorize?existing=1'),
      clientId: 'public-client',
      redirectUri: Uri.parse('http://127.0.0.1:8765/oauth/google/callback'),
      scopes: const ['openid', 'profile'],
    ),
    browserLauncher: launcher ?? RecordingLauncher(),
    callbackReceiver: CallbackQueue(callback),
    exchanger: exchanger ?? TestExchanger(),
    pkce: TestPkce(),
    stateGenerator: () => 'expected-state',
  );
}

void main() {
  test('dynamic callback port uses server redirect and opaque handoff', () async {
    final launcher = RecordingLauncher();
    final exchanger = TestExchanger();
    final appCallback = Uri.parse('http://127.0.0.1:43123/oauth/callback');
    final client = BrowserOAuthClient(
      request: OAuthAuthorizationRequest(
        authorizationEndpoint:
            Uri.parse('http://127.0.0.1:8765/oauth/google/start'),
        clientId: 'local-agent',
        redirectUri:
            Uri.parse('http://127.0.0.1:8765/oauth/google/callback'),
        scopes: const ['openid'],
      ),
      browserLauncher: launcher,
      callbackReceiver: DynamicCallbackQueue(
          appCallback.replace(queryParameters: {
            'handoff': 'opaque',
            'state': 'expected-state',
          }),
          appCallback),
      exchanger: exchanger,
      pkce: TestPkce(),
      stateGenerator: () => 'expected-state',
    );
    await client.authorize();
    expect(launcher.launched!.queryParameters['redirect_uri'],
        'http://127.0.0.1:8765/oauth/google/callback');
    expect(launcher.launched!.queryParameters['app_callback'],
        appCallback.toString());
    expect(exchanger.handoff, 'opaque');
    expect(exchanger.callbackUri!.port, 43123);
    expect(launcher.launched!.toString(), isNot(contains('access_token')));
  });

  test('start URL contains authorization code + PKCE parameters', () async {
    final launcher = RecordingLauncher();
    await expectLater(
      client(
              launcher: launcher,
              callback: Uri.parse(
                  'http://127.0.0.1:8765/oauth/google/callback?handoff=h&state=expected-state'))
          .authorize(),
      completes,
    );
    expect(launcher.launched!.queryParameters,
        containsPair('response_type', 'code'));
    expect(launcher.launched!.queryParameters,
        containsPair('client_id', 'public-client'));
    expect(launcher.launched!.queryParameters,
        containsPair('redirect_uri', 'http://127.0.0.1:8765/oauth/google/callback'));
    expect(launcher.launched!.queryParameters,
        containsPair('state', 'expected-state'));
    expect(launcher.launched!.queryParameters,
        containsPair('code_challenge', 'challenge'));
    expect(launcher.launched!.queryParameters,
        containsPair('code_challenge_method', 'S256'));
    expect(launcher.launched!.queryParameters, containsPair('existing', '1'));
  });

  test('callback success exchanges code without exposing a token', () async {
    final exchanger = TestExchanger();
    await client(
            callback: Uri.parse(
                'http://127.0.0.1:8765/oauth/google/callback?handoff=abc&state=expected-state'),
            exchanger: exchanger)
        .authorize();
    expect(exchanger.handoff, 'abc');
    expect(exchanger.verifier, 'verifier');
  });

  test('cancelled callback maps to cancelled', () async {
    await expectLater(
        client(callback: null).authorize(),
        throwsA(isA<AuthException>()
            .having((e) => e.code, 'code', AuthErrorCode.cancelled)));
  });

  test('state mismatch maps to stateMismatch', () async {
    await expectLater(
        client(
                callback:
                    Uri.parse('http://127.0.0.1:8765/oauth/google/callback?handoff=abc&state=wrong'))
            .authorize(),
        throwsA(isA<AuthException>()
            .having((e) => e.code, 'code', AuthErrorCode.stateMismatch)));
  });

  test('provider errors and denial are mapped', () async {
    await expectLater(
        client(
                callback: Uri.parse(
                    'http://127.0.0.1/callback?error=access_denied&state=expected-state'))
            .authorize(),
        throwsA(isA<AuthException>()
            .having((e) => e.code, 'code', AuthErrorCode.providerDenied)));
    await expectLater(
        client(
                callback: Uri.parse(
                    'http://127.0.0.1/callback?error=server_error&error_description=down&state=expected-state'))
            .authorize(),
        throwsA(isA<AuthException>()
            .having((e) => e.code, 'code', AuthErrorCode.providerError)));
  });

  test('login controller stores opaque session and logout clears it', () async {
    final storage = MemoryStorage();
    final controller = LoginController(
        oauth: client(
            callback: Uri.parse(
                'http://127.0.0.1:8765/oauth/google/callback?handoff=abc&state=expected-state')),
        storage: storage);
    await controller.login();
    expect(controller.model.state, AuthState.signedIn);
    expect(storage.value!.sessionId, 'opaque-session');
    await controller.logout();
    expect(controller.model.state, AuthState.signedOut);
    expect(storage.value, isNull);
    expect(storage.clears, 1);
  });

  test('expired stored session is cleared and reported', () async {
    final storage = MemoryStorage()
      ..value = SecureSession(sessionId: 'old', expiresAt: DateTime(2020));
    final controller =
        LoginController(oauth: client(callback: null), storage: storage);
    await controller.restoreSession(now: () => DateTime(2021));
    expect(controller.model.state, AuthState.expired);
    expect(storage.value, isNull);
  });

  test('authorization URL never contains a client secret or raw token',
      () async {
    final launcher = RecordingLauncher();
    await client(
            launcher: launcher,
            callback: Uri.parse(
                'http://127.0.0.1:8765/oauth/google/callback?handoff=abc&state=expected-state'))
        .authorize();
    expect(launcher.launched!.queryParameters.containsKey('client_secret'),
        isFalse);
    expect(launcher.launched!.queryParameters.containsKey('access_token'),
        isFalse);
    expect(launcher.launched!.queryParameters.containsKey('id_token'), isFalse);
  });
}
