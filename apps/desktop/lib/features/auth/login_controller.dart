import 'package:flutter/foundation.dart';

import '../../core/browser_auth/browser_auth.dart';

enum AuthState { signedOut, authorizing, signedIn, expired, error }

class LoginModel {
  const LoginModel({this.state = AuthState.signedOut, this.error});

  final AuthState state;
  final AuthException? error;

  bool get canLogin =>
      state == AuthState.signedOut ||
      state == AuthState.expired ||
      state == AuthState.error;
}

class LoginController extends ChangeNotifier {
  LoginController(
      {required BrowserOAuthClient oauth,
      required SecureSessionStorage storage})
      : _oauth = oauth,
        _storage = storage;

  final BrowserOAuthClient _oauth;
  final SecureSessionStorage _storage;
  LoginModel _model = const LoginModel();

  LoginModel get model => _model;

  Future<void> restoreSession({DateTime Function()? now}) async {
    final session = await _storage.read();
    if (session == null) return;
    if (session.isExpired((now ?? DateTime.now)())) {
      await _storage.clear();
      _model = const LoginModel(
          state: AuthState.expired,
          error:
              AuthException(AuthErrorCode.sessionExpired, 'Session expired'));
    } else {
      _model = const LoginModel(state: AuthState.signedIn);
    }
    notifyListeners();
  }

  Future<void> login() async {
    if (!_model.canLogin) return;
    _model = const LoginModel(state: AuthState.authorizing);
    notifyListeners();
    try {
      final session = await _oauth.authorize();
      await _storage.write(session);
      _model = const LoginModel(state: AuthState.signedIn);
    } on AuthException catch (error) {
      _model = LoginModel(
          state: error.code == AuthErrorCode.sessionExpired
              ? AuthState.expired
              : AuthState.error,
          error: error);
    } catch (error) {
      _model = LoginModel(
          state: AuthState.error,
          error: AuthException(AuthErrorCode.exchangeFailed, '$error'));
    }
    notifyListeners();
  }

  Future<void> logout() async {
    await _storage.clear();
    _model = const LoginModel(state: AuthState.signedOut);
    notifyListeners();
  }
}
