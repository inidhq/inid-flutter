// The pieces of the client that depend on the platform, behind small interfaces: the
// system's secure browser, secure storage and HTTP. The Flutter package plugs in
// flutter_web_auth_2 and flutter_secure_storage; tests plug in fakes.

/// Opens [url] in the system's secure browser (ASWebAuthenticationSession on iOS/macOS,
/// Chrome Custom Tabs on Android; never a WebView) and completes with the full URL InID
/// redirected to (`nube://callback?code=…&state=…`), or null when the person closed it.
abstract class InIDWebAuth {
  Future<String?> authenticate({required Uri url, required String callbackScheme});
}

/// Where the tokens are kept: the Keychain / Keystore in apps.
abstract class InIDStorage {
  Future<String?> read(String key);
  Future<void> write(String key, String value);
  Future<void> delete(String key);
}

class InIDHttpResponse {
  const InIDHttpResponse(this.status, this.body);
  final int status;
  final String body;
}

/// HTTP to InID. Throws on network errors.
abstract class InIDHttp {
  Future<InIDHttpResponse> get(Uri url);

  /// A form-encoded POST with exactly [headers] besides the content type: InID's token,
  /// refresh and revoke calls from an app never carry an Authorization header.
  Future<InIDHttpResponse> postForm(Uri url, Map<String, String> form, {Map<String, String> headers = const {}});
}

/// Keeps tokens in memory only (tests, or apps that don't want them to outlive the process).
class InIDMemoryStorage implements InIDStorage {
  final Map<String, String> values = {};

  @override
  Future<String?> read(String key) async => values[key];

  @override
  Future<void> write(String key, String value) async => values[key] = value;

  @override
  Future<void> delete(String key) async => values.remove(key);
}

/// Something went wrong talking to InID or with what it answered.
class InIDException implements Exception {
  const InIDException(this.code, {this.status, this.transient = false, this.cause});

  /// InID's OAuth error (`invalid_grant`, `access_denied`…) or one of this SDK's:
  /// `network_error`, `jwks_unavailable`, `invalid_id_token`, `state_mismatch`, `missing_code`.
  final String code;

  /// The HTTP status InID answered, when it answered.
  final int? status;

  /// True when InID couldn't be reached or failed (network, 5xx): trying again later may
  /// work, and the session is kept. False when InID said no.
  final bool transient;
  final Object? cause;

  @override
  String toString() => 'InIDException($code${status != null ? ', $status' : ''}${cause != null ? ': $cause' : ''})';
}
