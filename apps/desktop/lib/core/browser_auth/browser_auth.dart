import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';

/// Starts the system browser. Production implementations may use url_launcher;
/// tests should inject a recording implementation.
abstract interface class BrowserLauncher {
  Future<void> launch(Uri url);
}

/// Supplies the redirect received from a loopback listener or broker callback.
/// Returning null means that the user or host cancelled the flow.
abstract interface class AuthCallbackReceiver {
  Future<Uri?> waitForCallback();
}

abstract interface class PkceGenerator {
  String verifier();
  String challenge(String verifier);
}

class Sha256PkceGenerator implements PkceGenerator {
  @override
  String verifier() {
    final random = Random.secure();
    final bytes = List<int>.generate(32, (_) => random.nextInt(256));
    return _base64Url(bytes);
  }

  @override
  String challenge(String verifier) =>
      _base64Url(sha256.convert(utf8.encode(verifier)).bytes);

  String _base64Url(List<int> bytes) =>
      base64Url.encode(bytes).replaceAll('=', '');
}

class OAuthAuthorizationRequest {
  const OAuthAuthorizationRequest({
    required this.authorizationEndpoint,
    required this.clientId,
    required this.redirectUri,
    required this.scopes,
  });

  final Uri authorizationEndpoint;
  final String clientId;
  final Uri redirectUri;
  final List<String> scopes;
}

class OAuthAuthorizationStart {
  const OAuthAuthorizationStart({required this.url, required this.state});

  final Uri url;
  final String state;
}

class OAuthCallback {
  const OAuthCallback._({this.code, this.error, this.errorDescription});

  factory OAuthCallback.fromUri(Uri uri) => OAuthCallback._(
        code: uri.queryParameters['code'],
        error: uri.queryParameters['error'],
        errorDescription: uri.queryParameters['error_description'],
      );

  final String? code;
  final String? error;
  final String? errorDescription;

  bool get isSuccess => code != null && error == null;
}

enum AuthErrorCode {
  cancelled,
  callbackMissingCode,
  stateMismatch,
  providerDenied,
  providerError,
  invalidCallback,
  sessionExpired,
  exchangeFailed,
}

class AuthException implements Exception {
  const AuthException(this.code, this.message);

  final AuthErrorCode code;
  final String message;

  @override
  String toString() => 'AuthException($code): $message';
}

abstract interface class AuthorizationCodeExchanger {
  Future<SecureSession> exchange({required String code, required String verifier});
}

class BrowserOAuthClient {
  BrowserOAuthClient({
    required this.request,
    required this.browserLauncher,
    required this.callbackReceiver,
    required this.exchanger,
    PkceGenerator? pkce,
    String Function()? stateGenerator,
  })  : _pkce = pkce ?? Sha256PkceGenerator(),
        _stateGenerator = stateGenerator ?? _randomState;

  final OAuthAuthorizationRequest request;
  final BrowserLauncher browserLauncher;
  final AuthCallbackReceiver callbackReceiver;
  final AuthorizationCodeExchanger exchanger;
  final PkceGenerator _pkce;
  final String Function() _stateGenerator;

  Future<SecureSession> authorize() async {
    final verifier = _pkce.verifier();
    final state = _stateGenerator();
    final url = request.authorizationEndpoint.replace(queryParameters: {
      ...request.authorizationEndpoint.queryParameters,
      'response_type': 'code',
      'client_id': request.clientId,
      'redirect_uri': request.redirectUri.toString(),
      'scope': request.scopes.join(' '),
      'state': state,
      'code_challenge': _pkce.challenge(verifier),
      'code_challenge_method': 'S256',
    });
    await browserLauncher.launch(url);
    final callback = await callbackReceiver.waitForCallback();
    if (callback == null) {
      throw const AuthException(AuthErrorCode.cancelled, 'Authentication cancelled');
    }
    final callbackState = callback.queryParameters['state'];
    if (callbackState != state) {
      throw const AuthException(AuthErrorCode.stateMismatch, 'Authentication state mismatch');
    }
    final result = OAuthCallback.fromUri(callback);
    if (result.error != null) {
      if (result.error == 'access_denied') {
        throw const AuthException(AuthErrorCode.providerDenied, 'Authorization was denied');
      }
      throw AuthException(AuthErrorCode.providerError,
          result.errorDescription ?? result.error!);
    }
    if (!result.isSuccess) {
      throw const AuthException(AuthErrorCode.callbackMissingCode, 'Callback did not contain an authorization code');
    }
    try {
      return await exchanger.exchange(code: result.code!, verifier: verifier);
    } catch (error) {
      throw AuthException(AuthErrorCode.exchangeFailed, 'Authorization exchange failed: $error');
    }
  }

  static String _randomState() {
    final random = Random.secure();
    return base64Url.encode(List<int>.generate(24, (_) => random.nextInt(256))).replaceAll('=', '');
  }
}

class SecureSession {
  const SecureSession({required this.sessionId, required this.expiresAt});

  final String sessionId;
  final DateTime expiresAt;

  bool isExpired(DateTime now) => !expiresAt.isAfter(now);
}

abstract interface class SecureSessionStorage {
  Future<SecureSession?> read();
  Future<void> write(SecureSession session);
  Future<void> clear();
}
