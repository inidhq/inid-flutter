# inid_flutter

Sign in with [InID](https://inid.co) in Flutter apps: Face ID, a fingerprint or a code to the phone, no passwords.

The app is a **public client** of InID (RFC 8252). It has no secret key: it signs in with the authorization code flow and PKCE (S256), in the system's secure browser (ASWebAuthenticationSession on iOS and macOS, Chrome Custom Tabs on Android, never a WebView). InID sends the person back to the app's own scheme (`nube://callback`). The session is InID's ID token, verified on the device with InID's public keys, plus a refresh token that renews it. Both are kept in the Keychain or the Keystore.

Requires Dart 3.3+ and Flutter 3.19+.

## Install

```yaml
dependencies:
  inid_flutter: ^0.1.0
```

## Setup

Pick a scheme for your app, lowercase letters, digits, `+`, `-` and `.` only, for example `nube`. The redirect URI is that scheme with any path: `nube://callback`.

### 1. InID's panel

In your app's settings, add `nube://` to **allowed origins**. Any `nube://…` redirect URI is then accepted. For development, a loopback `http://127.0.0.1:<port>` also works.

### 2. Android

flutter_web_auth_2 receives the redirect in its callback activity. Add it to `android/app/src/main/AndroidManifest.xml`, inside `<application>`:

```xml
<activity
    android:name="com.linusu.flutter_web_auth_2.CallbackActivity"
    android:exported="true"
    android:taskAffinity="">
    <intent-filter android:label="flutter_web_auth_2">
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="nube" />
    </intent-filter>
</activity>
```

flutter_secure_storage has its own `minSdkVersion` requirement; check its README for the version you resolve.

### 3. iOS

ASWebAuthenticationSession catches the redirect by itself, so nothing is required. If the app also opens `nube://` links from elsewhere, register the scheme in `ios/Runner/Info.plist`:

```xml
<key>CFBundleURLTypes</key>
<array>
  <dict>
    <key>CFBundleURLName</key>
    <string>com.example.nube</string>
    <key>CFBundleURLSchemes</key>
    <array>
      <string>nube</string>
    </array>
  </dict>
</array>
```

On macOS, add the Keychain Sharing capability for flutter_secure_storage, and the outgoing network entitlement.

## Usage

```dart
import 'package:inid_flutter/inid_flutter.dart';

final inid = InID(
  publishableKey: 'pk_live_…',      // your publishable key; the app never has the secret one
  redirectUri: 'nube://callback',
  // issuer: 'https://id.inid.co',  // the default
  // scope: 'openid profile email phone',
);

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await inid.restore();             // the session kept on the device
  runApp(InIDProvider(inid: inid, child: const MyApp()));
}
```

### Widgets

```dart
const SignedOut(child: InIDSignInButton()),          // InID's black button, "Continuar con InID"
SignedIn(child: Text('Hola, ${InIDProvider.of(context).user?.firstName}')),
Protect(
  role: 'admin',                                     // and/or permission: 'invoices:read'
  fallback: const Text('Solo para administradores'),
  child: const AdminPanel(),
),
```

- `InIDProvider(inid:, locale:, child:)` makes the client available and rebuilds its dependents when the person signs in or out. `locale` is `es`, `en` or `pt`. Left out, the app's own locale is used, and any other language falls back to Spanish. The same language is passed to InID's page (`ui_locales`).
- `InIDSignInButton(entrance:, loginHint:, label:, expand:, onSignedIn:, onError:)`.
- `SignedIn` / `SignedOut` show nothing until `restore()` has finished.
- `Protect(role:, permission:, fallback:, child:)`: with neither `role` nor `permission`, it shows `child` to anyone signed in. It only hides UI. Your backend still checks.
- `InIDProvider.of(context)` returns the `InID`; `InIDProvider.textsOf(context)` returns the localized texts.

### The client

```dart
final user = await inid.signIn();                  // null if the person closed the browser
await inid.signIn(entrance: 'team');               // a door with its own rules, made in the panel
await inid.signIn(loginHint: '+56912345678');

inid.user;               // InIDUser? (id, firstName, lastName, name, email, emailVerified,
                         // phone, roles, permissions, publicMetadata)
inid.isSignedIn;
inid.has(role: 'admin');                  // false when signed out
inid.has(permission: 'invoices:read');
inid.userChanges.listen((user) { … });    // a Stream<InIDUser?>
// InID is also a ValueListenable<InIDUser?>: ValueListenableBuilder(valueListenable: inid, …)

await inid.signOut();
```

`signOut()` revokes the refresh token at InID (best effort, 3 s), deletes the tokens from the device, and makes the next sign-in ask again (`prompt=login`). Without that, the person would go straight back in. Their own InID stays signed in, because it belongs to them.

Errors come as `InIDException` with a `code` (InID's OAuth error, or `network_error`, `jwks_unavailable`, `invalid_id_token`, `state_mismatch`, `missing_code`). `transient` is true when InID couldn't be reached.

## Calling your backend

Send the ID token as a bearer token. `getToken()` renews it first when it ends within 60 seconds:

```dart
final token = await inid.getToken();   // null when nobody is signed in
final res = await http.get(
  Uri.parse('https://api.example.com/invoices'),
  headers: {'Authorization': 'Bearer $token'},
);
```

On the backend, verify it with an InID server SDK's bearer helper: `inid.bearer(request)` in `@inid/server`, `verify_bearer` in Python and Ruby, `VerifyBearer` in Go, `verifyBearer` in PHP and Java, `VerifyInIDBearerAsync()` in .NET, or Laravel's `inid.bearer` middleware. It runs the same checks as a session (InID's JWKS, RS256, `iss`, `aud == your publishable key`, `exp`) and gives you the same user with `has()`. Never trust a user id that the app sends in the request body.

## Sessions and offline

- `restore()` loads the kept session. A token that ends soon is renewed. If InID refuses the refresh token (the person signed out of the app elsewhere, or its authorization was taken back), the session ends and the tokens are deleted.
- Offline, the kept session stays: `user` is still there, `getToken()` returns the current token while it's valid and throws a transient `InIDException` once it has ended and can't be renewed.
- Only one renewal runs at a time. InID rotates the refresh token, so two parallel renewals would spend it twice.

## Without Flutter

`package:inid_flutter/inid_core.dart` is the same client in pure Dart (`InIDClient`). You pass in the platform pieces: `InIDWebAuth` (the secure browser), `InIDStorage` and, optionally, `InIDHttp`. `InID` takes the same parameters, so tests can pass fakes:

```dart
InID(
  publishableKey: 'pk_test_…',
  redirectUri: 'nube://callback',
  webAuth: myFakeBrowser,
  storage: InIDMemoryStorage(),
);
```

## Tests

```sh
docker run --rm -v "$PWD":/app -w /app ghcr.io/cirruslabs/flutter:stable sh -c "flutter pub get && flutter test"
```

## License

MIT
