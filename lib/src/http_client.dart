import 'package:http/http.dart' as http;

import 'platform.dart';

/// [InIDHttp] with package:http (pure Dart; works in apps and in tests).
class InIDHttpClient implements InIDHttp {
  InIDHttpClient({http.Client? client, this.timeout = const Duration(seconds: 15)}) : _client = client ?? http.Client();

  final http.Client _client;
  final Duration timeout;

  @override
  Future<InIDHttpResponse> get(Uri url) async {
    final res = await _client.get(url, headers: const {'accept': 'application/json'}).timeout(timeout);
    return InIDHttpResponse(res.statusCode, res.body);
  }

  @override
  Future<InIDHttpResponse> postForm(Uri url, Map<String, String> form, {Map<String, String> headers = const {}}) async {
    // A Map body is sent form-encoded (application/x-www-form-urlencoded)
    final res = await _client.post(url, headers: {'accept': 'application/json', ...headers}, body: form).timeout(timeout);
    return InIDHttpResponse(res.statusCode, res.body);
  }

  void close() => _client.close();
}
