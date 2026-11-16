import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' show sha256;
import 'package:pointycastle/export.dart';

import 'platform.dart';

// ---------- small helpers ----------

/// base64url without padding.
String b64url(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');

List<int> fromB64url(String text) => base64Url.decode(base64Url.normalize(text));

Map<String, dynamic> _jsonPart(String part) => Map<String, dynamic>.from(jsonDecode(utf8.decode(fromB64url(part))) as Map);

final Random _secure = Random.secure();

/// base64url of [bytes] random bytes from the platform's secure generator.
String randomToken([int bytes = 32]) => b64url(List<int>.generate(bytes, (_) => _secure.nextInt(256)));

/// PKCE S256: base64url(sha256(verifier)).
String codeChallenge(String verifier) => b64url(sha256.convert(ascii.encode(verifier)).bytes);

BigInt _unsigned(List<int> bytes) {
  var result = BigInt.zero;
  for (final b in bytes) {
    result = (result << 8) | BigInt.from(b);
  }
  return result;
}

// DER prefix of SHA-256's algorithm id, for RSASSA-PKCS1-v1_5
const _sha256DigestInfo = '0609608648016503040201';

/// Whether [signature] is a valid RS256 signature of [message] by [key].
bool verifyRs256(RSAPublicKey key, List<int> message, List<int> signature) {
  try {
    final signer = RSASigner(SHA256Digest(), _sha256DigestInfo)..init(false, PublicKeyParameter<RSAPublicKey>(key));
    return signer.verifySignature(Uint8List.fromList(message), RSASignature(Uint8List.fromList(signature)));
  } catch (_) {
    return false;
  }
}

// ---------- InID's public keys, kept an hour ----------

/// InID's signing keys (`{issuer}/.well-known/jwks.json`). Kept an hour; a key it doesn't
/// know (InID just rotated) is looked for at once, but once per key and at most once a
/// second, so tokens with made-up key ids can't make it ask InID again and again.
class InIDKeys {
  InIDKeys({required this.issuer, required InIDHttp http, DateTime Function()? clock})
      : _http = http,
        _clock = clock ?? DateTime.now;

  final String issuer;
  final InIDHttp _http;
  final DateTime Function() _clock;
  Map<String, RSAPublicKey> _keys = const {};
  DateTime? _fetchedAt;
  DateTime? _askedAt;
  final Set<String> _missed = {};

  Future<RSAPublicKey?> keyFor(String kid) async {
    final now = _clock();
    final fetchedAt = _fetchedAt;
    if (fetchedAt != null && now.difference(fetchedAt) < const Duration(hours: 1)) {
      final known = _keys[kid];
      if (known != null) return known;
      final askedAt = _askedAt;
      if (_missed.contains(kid) || (askedAt != null && now.difference(askedAt) < const Duration(seconds: 1))) return null;
      _missed.add(kid);
      if (_missed.length > 100) _missed.clear();
      _askedAt = now;
    }
    final InIDHttpResponse res;
    try {
      res = await _http.get(Uri.parse('$issuer/.well-known/jwks.json'));
    } catch (e) {
      throw InIDException('jwks_unavailable', transient: true, cause: e);
    }
    if (res.status != 200) throw InIDException('jwks_unavailable', status: res.status, transient: true);
    final keys = <String, RSAPublicKey>{};
    try {
      for (final jwk in (jsonDecode(res.body) as Map)['keys'] as List) {
        if (jwk is! Map || jwk['kty'] != 'RSA' || jwk['kid'] is! String) continue;
        keys[jwk['kid'] as String] = RSAPublicKey(_unsigned(fromB64url(jwk['n'] as String)), _unsigned(fromB64url(jwk['e'] as String)));
      }
    } catch (e) {
      throw InIDException('jwks_unavailable', status: res.status, transient: true, cause: e);
    }
    _keys = keys;
    _fetchedAt = now;
    return keys[kid];
  }
}

// ---------- ID tokens ----------

class VerifiedIdToken {
  const VerifiedIdToken(this.token, this.claims, this.exp, this.expired);
  final String token;
  final Map<String, dynamic> claims;

  /// When it ends, in seconds since 1970.
  final int exp;
  final bool expired;
}

/// An ID token InID signed for this app: its claims, or null. RS256 only; the key from
/// InID's JWKS by `kid`; `iss`, `aud` (the publishable key), `sub`, `exp`, and `nonce`
/// when given. An ended one still comes back (`expired: true`), so the session can be
/// renewed from it. Throws [InIDException] (transient) only when InID's keys can't be had.
Future<VerifiedIdToken?> verifyIdToken(
  String token, {
  required InIDKeys keys,
  required String issuer,
  required String audience,
  String? nonce,
  required DateTime now,
}) async {
  final parts = token.split('.');
  if (parts.length != 3) return null;
  final Map<String, dynamic> header;
  final Map<String, dynamic> claims;
  final List<int> signature;
  try {
    header = _jsonPart(parts[0]);
    claims = _jsonPart(parts[1]);
    signature = fromB64url(parts[2]);
  } catch (_) {
    return null;
  }
  final kid = header['kid'];
  if (header['alg'] != 'RS256' || kid is! String) return null;
  final key = await keys.keyFor(kid);
  if (key == null) return null;
  if (!verifyRs256(key, ascii.encode('${parts[0]}.${parts[1]}'), signature)) return null;
  return checkClaims(token, claims, issuer: issuer, audience: audience, nonce: nonce, now: now);
}

/// The claim checks of [verifyIdToken], without the signature.
VerifiedIdToken? checkClaims(String token, Map<String, dynamic> claims, {required String issuer, required String audience, String? nonce, required DateTime now}) {
  final exp = claims['exp'];
  if (claims['iss'] != issuer || claims['aud'] != audience || claims['sub'] is! String || exp is! num) return null;
  if (nonce != null && claims['nonce'] != nonce) return null;
  final seconds = now.millisecondsSinceEpoch ~/ 1000;
  return VerifiedIdToken(token, claims, exp.toInt(), exp <= seconds);
}

/// The claims of a token without checking its signature (only for a token this SDK already
/// verified and kept in secure storage).
Map<String, dynamic>? unverifiedClaims(String token) {
  final parts = token.split('.');
  if (parts.length != 3) return null;
  try {
    return _jsonPart(parts[1]);
  } catch (_) {
    return null;
  }
}
