import 'package:flutter/material.dart';

import 'inid.dart';
import 'texts.dart';
import 'user.dart';

/// Makes [inid] available below it and rebuilds what depends on it when the person signs
/// in or out.
///
/// ```dart
/// InIDProvider(inid: inid, child: MaterialApp(home: …))
/// ```
class InIDProvider extends InheritedNotifier<InID> {
  const InIDProvider({super.key, required InID inid, this.locale, required super.child}) : super(notifier: inid);

  /// es, en or pt for the widgets' texts and InID's page; by default the app's locale
  /// (Spanish when it's none of those).
  final String? locale;

  InID get inid => notifier!;

  static InIDProvider _of(BuildContext context) {
    final provider = context.dependOnInheritedWidgetOfExactType<InIDProvider>();
    if (provider == null) throw FlutterError('InID: this widget must be below an InIDProvider.');
    return provider;
  }

  /// The [InID] above [context]; the widget rebuilds when the user changes.
  static InID of(BuildContext context) => _of(context).inid;

  /// The widgets' texts in the provider's language, or the app's.
  static InIDTexts textsOf(BuildContext context) =>
      InIDTexts.of(_of(context).locale ?? Localizations.maybeLocaleOf(context)?.languageCode);

  @override
  bool updateShouldNotify(InIDProvider oldWidget) => super.updateShouldNotify(oldWidget) || oldWidget.locale != locale;
}

/// Shows [child] only when someone is signed in.
class SignedIn extends StatelessWidget {
  const SignedIn({super.key, required this.child});
  final Widget child;

  @override
  Widget build(BuildContext context) {
    final inid = InIDProvider.of(context);
    return inid.isLoaded && inid.isSignedIn ? child : const SizedBox.shrink();
  }
}

/// Shows [child] only when nobody is signed in (once the kept session was loaded).
class SignedOut extends StatelessWidget {
  const SignedOut({super.key, required this.child});
  final Widget child;

  @override
  Widget build(BuildContext context) {
    final inid = InIDProvider.of(context);
    return inid.isLoaded && !inid.isSignedIn ? child : const SizedBox.shrink();
  }
}

/// Shows [child] only to someone signed in with that [role] and/or [permission] (with
/// neither, to anyone signed in); to anyone else, [fallback]. It hides; the app's backend
/// still checks.
class Protect extends StatelessWidget {
  const Protect({super.key, this.role, this.permission, this.fallback, required this.child});
  final String? role;
  final String? permission;
  final Widget? fallback;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    final inid = InIDProvider.of(context);
    if (!inid.isLoaded) return const SizedBox.shrink();
    final user = inid.user;
    final allowed = user != null && user.has(role: role, permission: permission);
    return allowed ? child : (fallback ?? const SizedBox.shrink());
  }
}

/// InID's black button, "Continuar con InID": opens InID's sign-in in the system's secure
/// browser.
class InIDSignInButton extends StatefulWidget {
  const InIDSignInButton({
    super.key,
    this.entrance,
    this.loginHint,
    this.label,
    this.expand = false,
    this.onSignedIn,
    this.onError,
  });

  /// A door of the app with its own rules ("team"), made in InID's panel.
  final String? entrance;

  /// The phone or email to start with.
  final String? loginHint;

  /// Instead of "Continuar con InID".
  final String? label;

  /// As wide as it can be.
  final bool expand;

  /// After signing in (null when the person closed InID's page).
  final ValueChanged<InIDUser?>? onSignedIn;

  /// When signing in failed; without it, the error goes to [FlutterError.reportError].
  final void Function(Object error)? onError;

  @override
  State<InIDSignInButton> createState() => _InIDSignInButtonState();
}

const Color _ink = Color(0xFF18181B);
const Color _accent = Color(0xFFC6FF3D);

class _InIDSignInButtonState extends State<InIDSignInButton> {
  bool _busy = false;

  Future<void> _signIn(InID inid, String locale) async {
    setState(() => _busy = true);
    try {
      final user = await inid.signIn(entrance: widget.entrance, loginHint: widget.loginHint, locale: locale);
      widget.onSignedIn?.call(user);
    } catch (error, stack) {
      final onError = widget.onError;
      if (onError != null) {
        onError(error);
      } else {
        FlutterError.reportError(FlutterErrorDetails(exception: error, stack: stack, library: 'inid_flutter'));
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final inid = InIDProvider.of(context);
    final texts = InIDProvider.textsOf(context);
    final button = TextButton(
      onPressed: _busy ? null : () => _signIn(inid, texts.locale),
      style: TextButton.styleFrom(
        backgroundColor: _ink,
        foregroundColor: Colors.white,
        disabledBackgroundColor: _ink.withAlpha(200),
        disabledForegroundColor: Colors.white,
        minimumSize: const Size(0, 44),
        padding: const EdgeInsets.symmetric(horizontal: 16),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
        textStyle: const TextStyle(fontSize: 15, fontWeight: FontWeight.w600),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 9,
            height: 9,
            decoration: BoxDecoration(color: _accent, borderRadius: BorderRadius.circular(2)),
          ),
          const SizedBox(width: 9),
          Text(widget.label ?? texts.continueWith),
        ],
      ),
    );
    return widget.expand ? SizedBox(width: double.infinity, child: button) : button;
  }
}
