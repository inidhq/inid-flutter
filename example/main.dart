// A minimal app: InID's button when signed out, the person and a call to the app's own
// backend when signed in.
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:inid_flutter/inid_flutter.dart';

final inid = InID(
  publishableKey: 'pk_test_your_key',
  // Register `nube://` in InID's panel (allowed origins) and the `nube` scheme in the app
  redirectUri: 'nube://callback',
);

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await inid.restore();
  runApp(InIDProvider(inid: inid, locale: 'es', child: const MaterialApp(home: Home())));
}

class Home extends StatelessWidget {
  const Home({super.key});

  // The app's backend verifies the bearer token with an InID server SDK
  Future<String> loadInvoices() async {
    final token = await inid.getToken();
    final res = await http.get(
      Uri.parse('https://api.example.com/invoices'),
      headers: {if (token != null) 'Authorization': 'Bearer $token'},
    );
    return res.body;
  }

  @override
  Widget build(BuildContext context) {
    final user = InIDProvider.of(context).user;
    return Scaffold(
      body: Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const SignedOut(child: InIDSignInButton()),
            SignedIn(
              child: Column(children: [
                Text('Hola, ${user?.firstName ?? user?.email ?? ''}'),
                Protect(
                  role: 'admin',
                  fallback: const Text('Solo para administradores'),
                  child: TextButton(onPressed: loadInvoices, child: const Text('Facturas')),
                ),
                TextButton(onPressed: inid.signOut, child: Text(InIDProvider.textsOf(context).signOut)),
              ]),
            ),
          ],
        ),
      ),
    );
  }
}
