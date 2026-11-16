import 'dart:convert';

import 'package:crypto/crypto.dart' show sha256;
import 'package:flutter_test/flutter_test.dart';
import 'package:inid_flutter/inid_core.dart';
import 'package:pointycastle/export.dart';

import 'support/fake_inid.dart';

late AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> rsa;
late AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> otherRsa;

class Setup {
  Setup() {
    fake = FakeInID(rsa, clock);
    // The ID token for a code carries the nonce of the sign-in that's open
    fake.nonceFor = (_) => web.opened.last.queryParameters['nonce'];
    client = InIDClient(publishableKey: pk, issuer: '$issuer/', redirectUri: redirectUri, webAuth: web, storage: storage, http: fake, clock: clock.call);
  }
  final clock = FakeClock();
  final web = FakeWebAuth();
  final storage = InIDMemoryStorage();
  late final FakeInID fake;
  late final InIDClient client;
}

void main() {
  setUpAll(() {
    rsa = generateRsaKey();
    otherRsa = generateRsaKey();
  });

  group('signIn', () {
    test('opens InID with PKCE, state, nonce, client_id and redirect_uri', () async {
      final s = Setup();
      final user = await s.client.signIn();
      expect(user?.id, 'user_1');
      final url = s.web.opened.single;
      final q = url.queryParameters;
      expect('${url.scheme}://${url.host}${url.path}', '$issuer/oauth/authorize');
      expect(q['client_id'], pk);
      expect(q['redirect_uri'], redirectUri);
      expect(q['response_type'], 'code');
      expect(q['scope'], 'openid profile email phone');
      expect(q['code_challenge_method'], 'S256');
      expect(q['state'], matches(RegExp(r'^[\w-]{22}$')));
      expect(q['nonce'], matches(RegExp(r'^[\w-]{22}$')));
      expect(q['state'], isNot(q['nonce']));
      expect(q.containsKey('prompt'), isFalse);
      expect(q.containsKey('entrance'), isFalse);
      expect(s.web.schemes.single, 'nube');
      // The challenge is base64url(sha256(the verifier sent with the code))
      final verifier = s.fake.to('/oauth/token').single.form['code_verifier']!;
      expect(verifier.length, greaterThanOrEqualTo(43));
      final challenge = base64Url.encode(sha256.convert(ascii.encode(verifier)).bytes).replaceAll('=', '');
      expect(q['code_challenge'], challenge);
    });

    test('passes entrance, login_hint and ui_locales', () async {
      final s = Setup();
      await s.client.signIn(entrance: 'team', loginHint: '+56912345678', locale: 'en');
      final q = s.web.opened.single.queryParameters;
      expect(q['entrance'], 'team');
      expect(q['login_hint'], '+56912345678');
      expect(q['ui_locales'], 'en');
    });

    test('every sign-in has its own state, nonce and verifier', () async {
      final s = Setup();
      await s.client.signIn();
      await s.client.signIn();
      final [a, b] = s.web.opened;
      expect(a.queryParameters['state'], isNot(b.queryParameters['state']));
      expect(a.queryParameters['nonce'], isNot(b.queryParameters['nonce']));
      expect(a.queryParameters['code_challenge'], isNot(b.queryParameters['code_challenge']));
    });

    test('exchanges the code with client_id and no Authorization header', () async {
      final s = Setup();
      await s.client.signIn();
      final exchange = s.fake.to('/oauth/token').single;
      expect(exchange.form['grant_type'], 'authorization_code');
      expect(exchange.form['code'], 'code_1');
      expect(exchange.form['redirect_uri'], redirectUri);
      expect(exchange.form['client_id'], pk);
      expect(exchange.form.containsKey('client_secret'), isFalse);
      expect(exchange.headers.keys.map((k) => k.toLowerCase()), isNot(contains('authorization')));
    });

    test('keeps the tokens and the user', () async {
      final s = Setup();
      final changes = <InIDUser?>[];
      s.client.userChanges.listen(changes.add);
      final user = await s.client.signIn();
      expect(user!.name, 'Ana Pérez');
      expect(s.client.isSignedIn, isTrue);
      expect(s.client.claims['sub'], 'user_1');
      expect(s.storage.values['inid.$pk.id_token'], isNotNull);
      expect(s.storage.values['inid.$pk.refresh_token'], 'rt_1');
      await Future<void>.delayed(Duration.zero);
      expect(changes.last?.id, 'user_1');
    });

    test('null when the person closes the browser', () async {
      final s = Setup();
      s.web.answer = (_) => null;
      expect(await s.client.signIn(), isNull);
      expect(s.fake.to('/oauth/token'), isEmpty);
    });

    test('a different state is refused', () async {
      final s = Setup();
      s.web.answer = (_) => '$redirectUri?code=code_1&state=other';
      await expectLater(s.client.signIn(), throwsA(isA<InIDException>().having((e) => e.code, 'code', 'state_mismatch')));
      expect(s.fake.to('/oauth/token'), isEmpty);
    });

    test("InID's error comes back as an InIDException", () async {
      final s = Setup();
      s.web.answer = (url) => '$redirectUri?error=access_denied&state=${url.queryParameters['state']}';
      await expectLater(s.client.signIn(), throwsA(isA<InIDException>().having((e) => e.code, 'code', 'access_denied')));
    });

    test('an ID token with another nonce is refused', () async {
      final s = Setup();
      s.fake.nonceFor = (_) => 'another-nonce';
      await expectLater(s.client.signIn(), throwsA(isA<InIDException>().having((e) => e.code, 'code', 'invalid_id_token')));
      expect(s.client.isSignedIn, isFalse);
      expect(s.storage.values, isEmpty);
    });
  });

  group('verifyIdToken', () {
    late FakeClock clock;
    late FakeInID fake;
    late InIDKeys keys;
    setUp(() {
      clock = FakeClock();
      fake = FakeInID(rsa, clock);
      keys = InIDKeys(issuer: issuer, http: fake, clock: clock.call);
    });
    Future<VerifiedIdToken?> verify(String token, {String? nonce}) =>
        verifyIdToken(token, keys: keys, issuer: issuer, audience: pk, nonce: nonce, now: clock.now);

    test('a valid token', () async {
      final checked = await verify(fake.idToken(nonce: 'n1'), nonce: 'n1');
      expect(checked, isNotNull);
      expect(checked!.claims['sub'], 'user_1');
      expect(checked.expired, isFalse);
    });

    test('wrong aud', () async {
      expect(await verify(fake.idToken(extra: {'aud': 'pk_test_other'})), isNull);
    });

    test('wrong iss', () async {
      expect(await verify(fake.idToken(extra: {'iss': 'https://evil.test'})), isNull);
    });

    test('wrong nonce', () async {
      expect(await verify(fake.idToken(nonce: 'n1'), nonce: 'n2'), isNull);
      expect(await verify(fake.idToken(), nonce: 'n2'), isNull);
    });

    test('bad signature', () async {
      final forged = signJwt({'iss': issuer, 'aud': pk, 'sub': 'user_1', 'exp': clock.seconds + 600}, otherRsa.privateKey);
      expect(await verify(forged), isNull);
      // Claims swapped under a real signature
      final real = fake.idToken().split('.');
      final other = fake.idToken(extra: {'sub': 'user_2'}).split('.');
      expect(await verify('${real[0]}.${other[1]}.${real[2]}'), isNull);
    });

    test('unknown kid, other alg, malformed', () async {
      expect(await verify(signJwt({'iss': issuer, 'aud': pk, 'sub': 'u', 'exp': clock.seconds + 600}, rsa.privateKey, kid: 'nope')), isNull);
      expect(await verify(signJwt({'iss': issuer, 'aud': pk, 'sub': 'u', 'exp': clock.seconds + 600}, rsa.privateKey, alg: 'HS256')), isNull);
      expect(await verify('not.a.jwt'), isNull);
      expect(await verify('nope'), isNull);
    });

    test('expired still verifies, marked expired', () async {
      final checked = await verify(fake.idToken(lifetime: -5));
      expect(checked?.expired, isTrue);
    });

    test('keys are fetched once; an unknown kid at most once', () async {
      await verify(fake.idToken());
      await verify(fake.idToken());
      final unknown = signJwt({'iss': issuer, 'aud': pk, 'sub': 'u', 'exp': clock.seconds + 600}, rsa.privateKey, kid: 'k9');
      clock.now = clock.now.add(const Duration(seconds: 2));
      await verify(unknown);
      clock.now = clock.now.add(const Duration(seconds: 2));
      await verify(unknown);
      expect(fake.to('/.well-known/jwks.json').length, 2);
    });
  });

  group('getToken', () {
    test('returns the ID token while it has more than 60 s left', () async {
      final s = Setup();
      await s.client.signIn();
      final token = await s.client.getToken();
      expect(token, s.storage.values['inid.$pk.id_token']);
      s.clock.now = s.clock.now.add(const Duration(seconds: 530));
      expect(await s.client.getToken(), token);
      expect(s.fake.to('/oauth/token').length, 1);
    });

    test('renews within 60 s of exp, with client_id and no Authorization header', () async {
      final s = Setup();
      await s.client.signIn();
      final first = await s.client.getToken();
      s.clock.now = s.clock.now.add(const Duration(seconds: 545));
      final renewed = await s.client.getToken();
      expect(renewed, isNot(first));
      final refresh = s.fake.to('/oauth/token').last;
      expect(refresh.form, {'grant_type': 'refresh_token', 'refresh_token': 'rt_1', 'client_id': pk});
      expect(refresh.headers.keys.map((k) => k.toLowerCase()), isNot(contains('authorization')));
      expect(s.storage.values['inid.$pk.id_token'], renewed);
      expect(s.storage.values['inid.$pk.refresh_token'], 'rt_2');
    });

    test('renews once for calls at the same time', () async {
      final s = Setup();
      await s.client.signIn();
      s.clock.now = s.clock.now.add(const Duration(seconds: 590));
      final tokens = await Future.wait([s.client.getToken(), s.client.getToken(), s.client.getToken()]);
      expect(tokens.toSet().length, 1);
      expect(s.fake.to('/oauth/token').where((r) => r.form['grant_type'] == 'refresh_token').length, 1);
    });

    test('InID refusing the refresh ends the session', () async {
      final s = Setup();
      await s.client.signIn();
      s.clock.now = s.clock.now.add(const Duration(seconds: 700));
      s.fake.tokenAnswers.add((_) => const InIDHttpResponse(400, '{"error":"invalid_grant"}'));
      expect(await s.client.getToken(), isNull);
      expect(s.client.user, isNull);
      expect(s.storage.values, isEmpty);
    });

    test('offline: a token still valid is kept; an ended one throws', () async {
      final s = Setup();
      await s.client.signIn();
      final token = await s.client.getToken();
      s.clock.now = s.clock.now.add(const Duration(seconds: 570));
      s.fake.offline = true;
      expect(await s.client.getToken(), token);
      s.clock.now = s.clock.now.add(const Duration(seconds: 60));
      await expectLater(s.client.getToken(), throwsA(isA<InIDException>().having((e) => e.transient, 'transient', isTrue)));
      expect(s.client.isSignedIn, isTrue);
      expect(s.storage.values['inid.$pk.refresh_token'], 'rt_1');
    });

    test('null when nobody signed in', () async {
      final s = Setup();
      expect(await s.client.getToken(), isNull);
      expect(s.client.isLoaded, isTrue);
    });
  });

  group('restore', () {
    test('loads the kept session', () async {
      final s = Setup();
      s.storage.values['inid.$pk.id_token'] = s.fake.idToken();
      s.storage.values['inid.$pk.refresh_token'] = 'rt_0';
      await s.client.restore();
      expect(s.client.isLoaded, isTrue);
      expect(s.client.user?.email, 'ana@example.com');
      expect(s.fake.to('/oauth/token'), isEmpty);
    });

    test('renews a kept token that has ended', () async {
      final s = Setup();
      s.storage.values['inid.$pk.id_token'] = s.fake.idToken(lifetime: -100);
      s.storage.values['inid.$pk.refresh_token'] = 'rt_0';
      await s.client.restore();
      expect(s.client.isSignedIn, isTrue);
      expect(s.fake.to('/oauth/token').single.form['refresh_token'], 'rt_0');
      expect(s.storage.values['inid.$pk.refresh_token'], 'rt_1');
    });

    test('drops a token signed by someone else', () async {
      final s = Setup();
      s.storage.values['inid.$pk.id_token'] = signJwt({'iss': issuer, 'aud': pk, 'sub': 'x', 'exp': s.clock.seconds + 600}, otherRsa.privateKey);
      await s.client.restore();
      expect(s.client.isSignedIn, isFalse);
      expect(s.storage.values, isEmpty);
    });
  });

  group('signOut', () {
    test('revokes with client_id, clears storage, and asks next time', () async {
      final s = Setup();
      await s.client.signIn();
      await s.client.signOut();
      final revoke = s.fake.to('/oauth/revoke').single;
      expect(revoke.form, {'token': 'rt_1', 'token_type_hint': 'refresh_token', 'client_id': pk});
      expect(revoke.headers.keys.map((k) => k.toLowerCase()), isNot(contains('authorization')));
      expect(s.client.user, isNull);
      expect(s.storage.values.keys, ['inid.$pk.signed_out']);
      expect(await s.client.getToken(), isNull);

      await s.client.signIn();
      expect(s.web.opened.last.queryParameters['prompt'], 'login');
      // Signed in again: the one after that doesn't ask
      expect(s.storage.values.containsKey('inid.$pk.signed_out'), isFalse);
      await s.client.signIn();
      expect(s.web.opened.last.queryParameters.containsKey('prompt'), isFalse);
    });

    test('signs out even when InID cannot be reached', () async {
      final s = Setup();
      await s.client.signIn();
      s.fake.offline = true;
      await s.client.signOut();
      expect(s.client.isSignedIn, isFalse);
      expect(s.storage.values.keys, ['inid.$pk.signed_out']);
    });
  });

  group('InIDUser', () {
    test('from claims', () {
      final user = InIDUser.fromClaims({
        'sub': 'u1',
        'given_name': 'Ana',
        'email_verified': 'yes',
        'roles': ['admin', 3],
        'public_metadata': [1],
      });
      expect(user.name, 'Ana');
      expect(user.lastName, isNull);
      expect(user.emailVerified, isFalse);
      expect(user.roles, ['admin']);
      expect(user.permissions, isEmpty);
      expect(user.publicMetadata, isEmpty);
      expect(InIDUser.fromClaims({'sub': 'u2', 'name': 'Bo'}).name, 'Bo');
      expect(InIDUser.fromJson(user.toJson()).toJson(), user.toJson());
    });

    test('has()', () {
      const user = InIDUser(id: 'u1', roles: ['admin'], permissions: ['invoices:read']);
      expect(user.has(role: 'admin'), isTrue);
      expect(user.has(role: 'owner'), isFalse);
      expect(user.has(permission: 'invoices:read'), isTrue);
      expect(user.has(permission: 'invoices:write'), isFalse);
      expect(user.has(role: 'admin', permission: 'invoices:read'), isTrue);
      expect(user.has(role: 'admin', permission: 'invoices:write'), isFalse);
      // Neither: true for someone signed in
      expect(user.has(), isTrue);
    });

    test('client.has() is false when signed out', () async {
      final s = Setup();
      expect(s.client.has(role: 'admin'), isFalse);
      expect(s.client.has(), isFalse);
      await s.client.signIn();
      expect(s.client.has(), isTrue);
      expect(s.client.has(role: 'admin'), isTrue);
      expect(s.client.has(permission: 'invoices:read'), isTrue);
    });
  });

  test('a publishable key is required', () {
    expect(
      () => InIDClient(publishableKey: 'sk_live_x', redirectUri: redirectUri, webAuth: FakeWebAuth(), storage: InIDMemoryStorage()),
      throwsArgumentError,
    );
  });
}
