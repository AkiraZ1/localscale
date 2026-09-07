import 'browser_auth.dart';

BrowserLauncher systemBrowserLauncher() =>
    throw UnsupportedError('System browser login is unavailable on Web');
AuthCallbackReceiver loopbackCallbackReceiver() =>
    throw UnsupportedError('Loopback callbacks are unavailable on Web');
AuthorizationCodeExchanger localSessionBridge(Uri agentBase) =>
    throw UnsupportedError('Local agent sessions are unavailable on Web');
