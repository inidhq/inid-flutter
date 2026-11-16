import 'dart:async';
import 'dart:convert';

import 'http_client.dart';
import 'jwt.dart';
import 'platform.dart';
import 'user.dart';

const String defaultIssuer = 'https://id.inid.co';
const String defaultScope = 'openid profile email phone';

// A token with less than this left is renewed now, not in the middle of the next request
const int _renewBeforeSeconds = 60;
const Duration _revokeTimeout = Duration(seconds: 3);

/// Sign-in with InID for a native app, in pure Dart: the platform pieces (secure browser,
/// secure storage, HTTP) come in through [InIDWebAuth], [InIDStorage] and [InIDHttp].
/// Flutter apps use `InID`, which plugs in flutter_web_auth_2 and flutter_secure_storage.
///
/// The app is a public client of InID (RFC 8252): its publishable key is the client id and
/// it has no secret. Signing in is the authorization code flow with PKCE in the system's
/// secure browser, back to a custom scheme (`nube://callback`). The session is InID's ID
/// token (ten minutes, verified with InID's public keys) and a refresh token that renews
/// it, both in secure storage.
class InIDClient {
  InIDClient({
    required this.publishableKey,
    String issuer = defaultIssuer,
    required this.redirectUri,
    this.scope = defaultScope,
    required InIDWebAuth webAuth,
    required InIDStorage storage,
    InIDHttp? http,
    DateTime Function()? clock,
  })  : issuer = issuer.replaceFirst(RegExp(r'/+$'), ''),
        _webAuth = webAuth,
        _storage = storage,
        _http = http ?? InIDHttpClient(),
        _clock = clock ?? DateTime.now {
    if (!publishableKey.startsWith('pk_')) {
      throw ArgumentError.value(publishableKey, 'publishableKey', 'InID: set it to your publishable key (pk_...)');
    }
    final scheme = Uri.tryParse(redirectUri)?.scheme ?? '';
    if (scheme.isEmpty) {
      throw ArgumentError.value(redirectUri, 'redirectUri', 'InID: use your app\'s scheme, e.g. myapp://callback');
    }
    _keys = InIDKeys(issuer: this.issuer, http: _http, clock: _clock);
  }

  /// The app's publishable key (`pk_test_…` / `pk_live_…`): the OAuth client id.
  final String publishableKey;

  /// InID itself, without a trailing slash.
  final String issuer;

  /// Where InID sends the person back: the app's scheme, registered in InID's panel as an
  /// allowed origin (`nube://`), e.g. `nube://callback`.
  final String redirectUri;
  final String scope;

  final InIDWebAuth _webAuth;
  final InIDStorage _storage;
  final InIDHttp _http;
  final DateTime Function() _clock;
  late final InIDKeys _keys;

  late final String _idTokenKey = 'inid.$publishableKey.id_token';
  late final String _refreshTokenKey = 'inid.$publishableKey.refresh_token';
  late final String _signedOutKey = 'inid.$publishableKey.signed_out';

  final StreamController<InIDUser?> _changes = StreamController<InIDUser?>.broadcast();
  InIDUser? _user;
  bool _loaded = false;
  String? _idToken;
  String? _refreshToken;
  int _exp = 0;
  Map<String, dynamic> _claims = const {};
  Future<void>? _restoring;
  Future<String?>? _renewing;

  /// Who is signed in, or null.
  InIDUser? get user => _user;
  bool get isSignedIn => _user != null;

  /// Whether [restore] has finished: until then, nobody is known to be signed in or out.
  bool get isLoaded => _loaded;

  /// The current ID token's claims (`sid`, `auth_time`…), empty when signed out.
  Map<String, dynamic> get claims => _claims;

  /// The user each time it changes (signed in, renewed, signed out), and once [restore] ends.
  Stream<InIDUser?> get userChanges => _changes.stream;

  /// Whether the person signed in has the role, the permission, or both.
  bool has({String? role, String? permission}) => _user?.has(role: role, permission: permission) ?? false;

  /// Called after every change of [user] or [isLoaded]; subclasses notify their listeners.
  void didChange() {}

  void _emit() {
    if (!_changes.isClosed) _changes.add(_user);
    didChange();
  }

  int get _nowSeconds => _clock().millisecondsSinceEpoch ~/ 1000;

  Future<VerifiedIdToken?> _verify(String token, {String? nonce}) =>
      verifyIdToken(token, keys: _keys, issuer: issuer, audience: publishableKey, nonce: nonce, now: _clock());

  // ---------- the session kept on the device ----------

  /// Loads the session kept in secure storage (call once at startup). A token about to end
  /// is renewed. Offline, the kept session stays: the person is still signed in, and
  /// [getToken] renews it when InID can be reached again.
  Future<void> restore() => _restoring ??= _restore();

  Future<void> _restore() async {
    try {
      final idToken = await _storage.read(_idTokenKey);
      final refreshToken = await _storage.read(_refreshTokenKey);
      _refreshToken = refreshToken;
      VerifiedIdToken? current;
      if (idToken != null) {
        try {
          current = await _verify(idToken);
        } on InIDException catch (e) {
          if (!e.transient) rethrow;
          // InID's keys can't be had now: this token was verified before it was kept
          final claims = unverifiedClaims(idToken);
          current = claims == null ? null : checkClaims(idToken, claims, issuer: issuer, audience: publishableKey, now: _clock());
        }
      }
      if (current != null) {
        _use(current, refreshToken);
      } else if (idToken != null) {
        await _storage.delete(_idTokenKey);
      }
      final needsRenewal = current == null || current.exp - _nowSeconds <= _renewBeforeSeconds;
      if (refreshToken != null && needsRenewal) {
        try {
          await _renewOnce();
        } on InIDException catch (e) {
          if (!e.transient) return;
          // Offline: a session that can't be renewed now is kept, unless there's no user
        }
      } else if (refreshToken == null && current != null && current.expired) {
        await _forget();
      }
    } finally {
      _loaded = true;
      _emit();
    }
  }

  void _use(VerifiedIdToken token, String? refreshToken) {
    _idToken = token.token;
    _refreshToken = refreshToken;
    _exp = token.exp;
    _claims = token.claims;
    _user = InIDUser.fromClaims(token.claims);
  }

  Future<void> _keep(VerifiedIdToken token, String? refreshToken) async {
    await _storage.write(_idTokenKey, token.token);
    if (refreshToken != null) {
      await _storage.write(_refreshTokenKey, refreshToken);
    } else {
      await _storage.delete(_refreshTokenKey);
    }
    _use(token, refreshToken);
  }

  // Ends the session on this device (not at InID)
  Future<void> _forget() async {
    _idToken = null;
    _refreshToken = null;
    _exp = 0;
    _claims = const {};
    _user = null;
    await _storage.delete(_idTokenKey);
    await _storage.delete(_refreshTokenKey);
  }

  // ---------- InID's endpoints, as a public client ----------

  Future<Map<String, dynamic>> _token(Map<String, String> form) async {
    final InIDHttpResponse res;
    try {
      // client_id in the form and no Authorization header: the app has no secret
      res = await _http.postForm(Uri.parse('$issuer/oauth/token'), {...form, 'client_id': publishableKey});
    } catch (e) {
      throw InIDException('network_error', transient: true, cause: e);
    }
    Map<String, dynamic> body = const {};
    try {
      body = Map<String, dynamic>.from(jsonDecode(res.body) as Map);
    } catch (_) {}
    if (res.status < 200 || res.status >= 300) {
      final error = body['error'];
      throw InIDException(error is String ? error : 'token_failed', status: res.status, transient: res.status >= 500);
    }
    if (body['id_token'] is! String) throw InIDException('invalid_token_response', status: res.status);
    return body;
  }

  /// The address of InID's sign-in page for this flow.
  Uri authorizeUrl({
    required String state,
    required String nonce,
    required String codeVerifier,
    String? entrance,
    String? loginHint,
    String? locale,
    String? prompt,
  }) {
    final query = <String, String>{
      'client_id': publishableKey,
      'redirect_uri': redirectUri,
      'response_type': 'code',
      'scope': scope,
      'state': state,
      'nonce': nonce,
      'code_challenge': codeChallenge(codeVerifier),
      'code_challenge_method': 'S256',
      if (locale != null && locale.isNotEmpty) 'ui_locales': locale,
      if (loginHint != null && loginHint.isNotEmpty) 'login_hint': loginHint,
      if (prompt != null && prompt.isNotEmpty) 'prompt': prompt,
      if (entrance != null && entrance.isNotEmpty) 'entrance': entrance,
    };
    return Uri.parse('$issuer/oauth/authorize').replace(queryParameters: query);
  }

  // ---------- signing in and out ----------

  /// Opens InID's sign-in in the system's secure browser and comes back signed in. Null
  /// when the person closed it. [entrance]: a door of the app with its own rules ("team"),
  /// made in InID's panel. [loginHint]: the phone or email to start with. [locale]: es, en
  /// or pt. Throws [InIDException] when InID answers an error or the answer doesn't check.
  Future<InIDUser?> signIn({String? entrance, String? loginHint, String? locale}) async {
    final state = randomToken(16);
    final nonce = randomToken(16);
    final verifier = randomToken(32);
    // Right after signing out, InID asks: they chose to leave, so they aren't taken back
    // in by itself
    final signedOut = await _storage.read(_signedOutKey) == '1';
    final url = authorizeUrl(
      state: state,
      nonce: nonce,
      codeVerifier: verifier,
      entrance: entrance,
      loginHint: loginHint,
      locale: locale,
      prompt: signedOut ? 'login' : null,
    );
    final result = await _webAuth.authenticate(url: url, callbackScheme: Uri.parse(redirectUri).scheme);
    if (result == null) return null;
    final back = Uri.parse(result).queryParameters;
    if (back['state'] != state) throw const InIDException('state_mismatch');
    final error = back['error'];
    if (error != null) throw InIDException(error, cause: back['error_description']);
    final code = back['code'];
    if (code == null || code.isEmpty) throw const InIDException('missing_code');
    final tokens = await _token({
      'grant_type': 'authorization_code',
      'code': code,
      'redirect_uri': redirectUri,
      'code_verifier': verifier,
    });
    final verified = await _verify(tokens['id_token'] as String, nonce: nonce);
    if (verified == null) throw const InIDException('invalid_id_token');
    await _keep(verified, tokens['refresh_token'] as String?);
    await _storage.delete(_signedOutKey);
    _loaded = true;
    _emit();
    return _user;
  }

  /// The ID token to send to the app's backend (`Authorization: Bearer <token>`), renewed
  /// first when it ends within 60 seconds. Null when nobody is signed in (or InID ended the
  /// session). Throws a transient [InIDException] when it must be renewed and InID can't be
  /// reached.
  Future<String?> getToken() async {
    await restore();
    final idToken = _idToken;
    if (idToken != null && _exp - _nowSeconds > _renewBeforeSeconds) return idToken;
    if (_refreshToken == null) return idToken != null && _exp > _nowSeconds ? idToken : null;
    try {
      return await _renewOnce();
    } on InIDException catch (e) {
      if (!e.transient) return null;
      // InID can't be reached: what's still valid stays
      final current = _idToken;
      if (current != null && _exp > _nowSeconds) return current;
      rethrow;
    }
  }

  // One renewal at a time: InID rotates the refresh token, so two at once would spend it twice
  Future<String?> _renewOnce() => _renewing ??= _renew().whenComplete(() => _renewing = null);

  Future<String?> _renew() async {
    final refreshToken = _refreshToken;
    if (refreshToken == null) return null;
    try {
      final tokens = await _token({'grant_type': 'refresh_token', 'refresh_token': refreshToken});
      final verified = await _verify(tokens['id_token'] as String);
      if (verified == null) throw const InIDException('invalid_id_token');
      // Signed out (or in again) meanwhile: this renewal is for a session that's gone
      if (_refreshToken != refreshToken) return _idToken;
      await _keep(verified, (tokens['refresh_token'] as String?) ?? refreshToken);
      _emit();
      return verified.token;
    } on InIDException catch (e) {
      // InID said no (signed out elsewhere, authorization taken back): the session is over
      if (!e.transient && _refreshToken == refreshToken) {
        await _forget();
        _emit();
      }
      rethrow;
    }
  }

  /// Signs out of the app: the refresh token is revoked at InID (best effort), the tokens
  /// leave the device, and the next sign-in asks again (`prompt=login`). The person's own
  /// InID stays signed in (that's theirs).
  Future<void> signOut() async {
    final refreshToken = _refreshToken ?? await _storage.read(_refreshTokenKey);
    await _forget();
    await _storage.write(_signedOutKey, '1');
    _loaded = true;
    _emit();
    if (refreshToken != null) {
      try {
        await _http.postForm(Uri.parse('$issuer/oauth/revoke'), {
          'token': refreshToken,
          'token_type_hint': 'refresh_token',
          'client_id': publishableKey,
        }).timeout(_revokeTimeout);
      } catch (_) {}
    }
  }

  /// Stops [userChanges].
  void dispose() {
    _changes.close();
  }
}
