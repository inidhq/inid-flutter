import 'package:flutter/foundation.dart';

import 'client.dart';
import 'flutter_platform.dart';
import 'platform.dart';
import 'user.dart';

/// Sign-in with InID for a Flutter app.
///
/// ```dart
/// final inid = InID(publishableKey: 'pk_live_…', redirectUri: 'nube://callback');
/// await inid.restore();
/// final user = await inid.signIn();
/// final token = await inid.getToken(); // Authorization: Bearer <token> to your backend
/// ```
///
/// It is a [ValueListenable] of the user (null when signed out) and also notifies when
/// [isLoaded] changes; [userChanges] is the same as a stream.
class InID extends InIDClient implements ValueListenable<InIDUser?> {
  InID({
    required super.publishableKey,
    super.issuer,
    required super.redirectUri,
    super.scope,
    InIDWebAuth? webAuth,
    InIDStorage? storage,
    super.http,
    super.clock,
  }) : super(
          webAuth: webAuth ?? const FlutterWebAuth2InID(),
          storage: storage ?? const SecureStorageInID(),
        );

  final _Notifier _notifier = _Notifier();

  @override
  InIDUser? get value => user;

  @override
  void addListener(VoidCallback listener) => _notifier.addListener(listener);

  @override
  void removeListener(VoidCallback listener) => _notifier.removeListener(listener);

  @override
  void didChange() => _notifier.notify();

  @override
  void dispose() {
    super.dispose();
    _notifier.dispose();
  }
}

class _Notifier extends ChangeNotifier {
  void notify() => notifyListeners();
}
