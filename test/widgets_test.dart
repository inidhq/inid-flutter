import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:inid_flutter/inid_flutter.dart';
import 'package:pointycastle/export.dart';

import 'support/fake_inid.dart';

late AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> rsa;

void main() {
  setUpAll(() => rsa = generateRsaKey());

  late FakeClock clock;
  late FakeInID fake;
  late FakeWebAuth web;
  late InIDMemoryStorage storage;
  late InID inid;

  setUp(() {
    clock = FakeClock();
    fake = FakeInID(rsa, clock);
    web = FakeWebAuth();
    fake.nonceFor = (_) => web.opened.last.queryParameters['nonce'];
    storage = InIDMemoryStorage();
    inid = InID(publishableKey: pk, issuer: issuer, redirectUri: redirectUri, webAuth: web, storage: storage, http: fake, clock: clock.call);
  });

  Widget app({String? locale = 'es'}) => MaterialApp(
        home: InIDProvider(
          inid: inid,
          locale: locale,
          child: const Scaffold(
            body: Column(children: [
              SignedIn(child: Text('in')),
              SignedOut(child: InIDSignInButton()),
              Protect(role: 'admin', fallback: Text('not admin'), child: Text('admin area')),
              Protect(permission: 'invoices:write', fallback: Text('no write'), child: Text('write')),
              Protect(fallback: Text('anyone out'), child: Text('anyone in')),
            ]),
          ),
        ),
      );

  testWidgets('nothing shows until the kept session is loaded', (tester) async {
    await tester.pumpWidget(app());
    expect(find.text('in'), findsNothing);
    expect(find.text('Continuar con InID'), findsNothing);
    expect(find.text('not admin'), findsNothing);
  });

  testWidgets('signed out: the button and the fallbacks', (tester) async {
    await tester.pumpWidget(app());
    await tester.runAsync(inid.restore);
    await tester.pump();
    expect(find.text('in'), findsNothing);
    expect(find.text('Continuar con InID'), findsOneWidget);
    expect(find.text('not admin'), findsOneWidget);
    expect(find.text('admin area'), findsNothing);
    expect(find.text('no write'), findsOneWidget);
    expect(find.text('anyone out'), findsOneWidget);
    expect(find.text('anyone in'), findsNothing);
  });

  testWidgets('the button signs in, and SignedIn/Protect follow', (tester) async {
    await tester.pumpWidget(app());
    await tester.runAsync(inid.restore);
    await tester.pump();
    await tester.runAsync(() async {
      await tester.tap(find.text('Continuar con InID'));
      // Let the sign-in (fake browser, token exchange, verification) finish
      for (var i = 0; i < 50 && !inid.isSignedIn; i++) {
        await Future<void>.delayed(const Duration(milliseconds: 10));
      }
    });
    await tester.pump();
    expect(web.opened.single.queryParameters['ui_locales'], 'es');
    expect(find.text('in'), findsOneWidget);
    expect(find.text('Continuar con InID'), findsNothing);
    expect(find.text('admin area'), findsOneWidget);
    expect(find.text('not admin'), findsNothing);
    expect(find.text('no write'), findsOneWidget);
    // Protect with neither role nor permission: anyone signed in
    expect(find.text('anyone in'), findsOneWidget);
    expect(find.text('anyone out'), findsNothing);

    await tester.runAsync(inid.signOut);
    await tester.pump();
    expect(find.text('in'), findsNothing);
    expect(find.text('Continuar con InID'), findsOneWidget);
    expect(find.text('not admin'), findsOneWidget);
  });

  testWidgets("texts in English and Portuguese, or the app's language", (tester) async {
    await tester.runAsync(inid.restore);
    // A MaterialApp with no locales of its own is in English
    await tester.pumpWidget(app(locale: null));
    expect(find.text('Continue with InID'), findsOneWidget);
    await tester.pumpWidget(app(locale: 'en'));
    expect(find.text('Continue with InID'), findsOneWidget);
    await tester.pumpWidget(app(locale: 'pt'));
    expect(find.text('Continuar com InID'), findsOneWidget);
  });
}
