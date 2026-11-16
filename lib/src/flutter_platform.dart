import 'package:flutter/services.dart' show PlatformException;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_web_auth_2/flutter_web_auth_2.dart';

import 'platform.dart';

/// [InIDWebAuth] with flutter_web_auth_2: ASWebAuthenticationSession on iOS and macOS,
/// Chrome Custom Tabs on Android.
class FlutterWebAuth2InID implements InIDWebAuth {
  const FlutterWebAuth2InID({this.preferEphemeral = false});

  /// iOS/macOS: a private browser session (no cookies shared with Safari). Off by default,
  /// so someone already signed in to InID in Safari goes straight through.
  final bool preferEphemeral;

  @override
  Future<String?> authenticate({required Uri url, required String callbackScheme}) async {
    try {
      return await FlutterWebAuth2.authenticate(
        url: url.toString(),
        callbackUrlScheme: callbackScheme,
        options: FlutterWebAuth2Options(preferEphemeral: preferEphemeral),
      );
    } on PlatformException catch (e) {
      // The person closed the browser
      if (e.code == 'CANCELED') return null;
      rethrow;
    }
  }
}

/// [InIDStorage] with flutter_secure_storage: the Keychain on iOS/macOS, the Keystore on
/// Android.
class SecureStorageInID implements InIDStorage {
  const SecureStorageInID([this.storage = const FlutterSecureStorage()]);

  final FlutterSecureStorage storage;

  @override
  Future<String?> read(String key) => storage.read(key: key);

  @override
  Future<void> write(String key, String value) => storage.write(key: key, value: value);

  @override
  Future<void> delete(String key) => storage.delete(key: key);
}
