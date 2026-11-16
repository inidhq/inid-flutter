/// The words InID's widgets show, in Spanish, English and Portuguese.
class InIDTexts {
  const InIDTexts({required this.locale, required this.continueWith, required this.signOut, required this.securedBy});

  /// es, en or pt (what InID's page is shown in, too).
  final String locale;
  final String continueWith;
  final String signOut;
  final String securedBy;

  static const es = InIDTexts(locale: 'es', continueWith: 'Continuar con InID', signOut: 'Salir', securedBy: 'Protegido por InID');
  static const en = InIDTexts(locale: 'en', continueWith: 'Continue with InID', signOut: 'Sign out', securedBy: 'Secured by InID');
  static const pt = InIDTexts(locale: 'pt', continueWith: 'Continuar com InID', signOut: 'Sair', securedBy: 'Protegido por InID');

  /// The texts for a language code (`es`, `en-US`, `pt_BR`…); Spanish for any other.
  static InIDTexts of(String? languageCode) {
    switch (languageCode?.toLowerCase().split(RegExp('[-_]')).first) {
      case 'en':
        return en;
      case 'pt':
        return pt;
      default:
        return es;
    }
  }
}
