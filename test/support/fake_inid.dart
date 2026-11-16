// A fake InID for the tests: it serves a JWKS and signs ID tokens with a test RSA key,
// answers /oauth/token and /oauth/revoke, and records every request.
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:inid_flutter/inid_core.dart';
import 'package:pointycastle/export.dart';

const issuer = 'https://id.test';
const pk = 'pk_test_app';
const redirectUri = 'nube://callback';

String b64(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');

List<int> _bytes(BigInt n) {
  final out = <int>[];
  while (n > BigInt.zero) {
    out.insert(0, (n & BigInt.from(0xff)).toInt());
    n = n >> 8;
  }
  return out;
}

AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> generateRsaKey() {
  final seed = Random.secure();
  final random = FortunaRandom()..seed(KeyParameter(Uint8List.fromList(List.generate(32, (_) => seed.nextInt(256)))));
  final generator = RSAKeyGenerator()..init(ParametersWithRandom(RSAKeyGeneratorParameters(BigInt.from(65537), 2048, 64), random));
  final pair = generator.generateKeyPair();
  // The casts are needed with pointycastle 3, not with 4
  // ignore: unnecessary_cast
  return AsymmetricKeyPair(pair.publicKey as RSAPublicKey, pair.privateKey as RSAPrivateKey);
}

String signJwt(Map<String, dynamic> claims, RSAPrivateKey key, {String kid = 'k1', String alg = 'RS256'}) {
  final input = '${b64(utf8.encode(jsonEncode({'alg': alg, 'kid': kid, 'typ': 'JWT'})))}.${b64(utf8.encode(jsonEncode(claims)))}';
  final signer = RSASigner(SHA256Digest(), '0609608648016503040201')..init(true, PrivateKeyParameter<RSAPrivateKey>(key));
  return '$input.${b64(signer.generateSignature(Uint8List.fromList(ascii.encode(input))).bytes)}';
}

class Request {
  Request(this.method, this.url, this.form, this.headers);
  final String method;
  final Uri url;
  final Map<String, String> form;
  final Map<String, String> headers;
}

class FakeClock {
  DateTime now = DateTime.utc(2026, 11, 16, 12);
  int get seconds => now.millisecondsSinceEpoch ~/ 1000;
  DateTime call() => now;
}

class FakeInID implements InIDHttp {
  FakeInID(this.key, this.clock);

  final AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> key;
  final FakeClock clock;
  final List<Request> requests = [];

  /// Answers to /oauth/token, in order; by default a fresh pair of tokens.
  final List<InIDHttpResponse Function(Map<String, String> form)> tokenAnswers = [];
  bool offline = false;
  int issued = 0;

  /// The nonce the next ID token carries for an authorization code.
  String? Function(Map<String, String> form)? nonceFor;

  Iterable<Request> to(String path) => requests.where((r) => r.url.path == path);

  String idToken({Map<String, dynamic> extra = const {}, int lifetime = 600, String? nonce}) => signJwt({
        'iss': issuer,
        'aud': pk,
        'sub': 'user_1',
        'given_name': 'Ana',
        'family_name': 'Pérez',
        'email': 'ana@example.com',
        'email_verified': true,
        'phone_number': '+56912345678',
        'roles': ['admin'],
        'permissions': ['invoices:read'],
        'public_metadata': {'plan': 'pro'},
        'iat': clock.seconds,
        'exp': clock.seconds + lifetime,
        if (nonce != null) 'nonce': nonce,
        ...extra,
      }, key.privateKey);

  InIDHttpResponse tokens(Map<String, String> form, {int lifetime = 600}) {
    issued++;
    return InIDHttpResponse(
        200,
        jsonEncode({
          'id_token': idToken(lifetime: lifetime, nonce: form['grant_type'] == 'authorization_code' ? nonceFor?.call(form) : null),
          'refresh_token': 'rt_$issued',
          'access_token': 'at_$issued',
          'token_type': 'Bearer',
          'expires_in': lifetime,
        }));
  }

  @override
  Future<InIDHttpResponse> get(Uri url) async {
    requests.add(Request('GET', url, const {}, const {}));
    if (offline) throw Exception('offline');
    if (url.toString() == '$issuer/.well-known/jwks.json') {
      return InIDHttpResponse(
          200,
          jsonEncode({
            'keys': [
              {'kty': 'RSA', 'kid': 'k1', 'alg': 'RS256', 'use': 'sig', 'n': b64(_bytes(key.publicKey.modulus!)), 'e': b64(_bytes(key.publicKey.exponent!))}
            ]
          }));
    }
    return const InIDHttpResponse(404, '{"error":"not_found"}');
  }

  @override
  Future<InIDHttpResponse> postForm(Uri url, Map<String, String> form, {Map<String, String> headers = const {}}) async {
    requests.add(Request('POST', url, form, headers));
    if (offline) throw Exception('offline');
    if (url.toString() == '$issuer/oauth/token') {
      return tokenAnswers.isNotEmpty ? tokenAnswers.removeAt(0)(form) : tokens(form);
    }
    if (url.toString() == '$issuer/oauth/revoke') return const InIDHttpResponse(200, '');
    return const InIDHttpResponse(404, '{"error":"not_found"}');
  }
}

/// The secure browser: records the URL and answers with what [answer] returns.
class FakeWebAuth implements InIDWebAuth {
  final List<Uri> opened = [];
  final List<String> schemes = [];
  String? Function(Uri url)? answer;

  /// InID sends the person back with a code and the same state.
  static String? approve(Uri url) => '$redirectUri?code=code_1&state=${url.queryParameters['state']}';

  @override
  Future<String?> authenticate({required Uri url, required String callbackScheme}) async {
    opened.add(url);
    schemes.add(callbackScheme);
    return (answer ?? approve)(url);
  }
}
