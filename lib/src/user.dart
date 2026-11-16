/// The person signed in to the app, from InID's ID token.
class InIDUser {
  const InIDUser({
    required this.id,
    this.firstName,
    this.lastName,
    this.name,
    this.email,
    this.emailVerified = false,
    this.phone,
    this.roles = const [],
    this.permissions = const [],
    this.publicMetadata = const {},
  });

  /// The person's id at this app (InID gives each app its own): the token's `sub`.
  final String id;
  final String? firstName;
  final String? lastName;

  /// "firstName lastName", or the token's `name`.
  final String? name;
  final String? email;
  final bool emailVerified;

  /// E.164, e.g. +56912345678.
  final String? phone;

  /// The app's roles for this person, and what they allow (set in InID's panel or by the
  /// app's server); empty when the app has no roles.
  final List<String> roles;
  final List<String> permissions;

  /// What the app keeps public about this person.
  final Map<String, dynamic> publicMetadata;

  /// The user in an ID token's claims (same mapping as every InID SDK).
  factory InIDUser.fromClaims(Map<String, dynamic> claims) {
    String? text(Object? v) => v is String && v.isNotEmpty ? v : null;
    List<String> strings(Object? v) => v is List ? v.whereType<String>().toList(growable: false) : const [];
    final firstName = text(claims['given_name']);
    final lastName = text(claims['family_name']);
    final joined = [firstName, lastName].whereType<String>().join(' ');
    final metadata = claims['public_metadata'];
    return InIDUser(
      id: '${claims['sub']}',
      firstName: firstName,
      lastName: lastName,
      name: joined.isNotEmpty ? joined : text(claims['name']),
      email: text(claims['email']),
      emailVerified: claims['email_verified'] == true,
      phone: text(claims['phone_number']),
      roles: strings(claims['roles']),
      permissions: strings(claims['permissions']),
      publicMetadata: metadata is Map ? Map<String, dynamic>.from(metadata) : const {},
    );
  }

  /// The user as every InID SDK serializes it (camelCase).
  factory InIDUser.fromJson(Map<String, dynamic> json) {
    List<String> strings(Object? v) => v is List ? v.whereType<String>().toList(growable: false) : const [];
    final metadata = json['publicMetadata'];
    return InIDUser(
      id: '${json['id']}',
      firstName: json['firstName'] as String?,
      lastName: json['lastName'] as String?,
      name: json['name'] as String?,
      email: json['email'] as String?,
      emailVerified: json['emailVerified'] == true,
      phone: json['phone'] as String?,
      roles: strings(json['roles']),
      permissions: strings(json['permissions']),
      publicMetadata: metadata is Map ? Map<String, dynamic>.from(metadata) : const {},
    );
  }

  Map<String, dynamic> toJson() => {
        'id': id,
        'firstName': firstName,
        'lastName': lastName,
        'name': name,
        'email': email,
        'emailVerified': emailVerified,
        'phone': phone,
        'roles': roles,
        'permissions': permissions,
        'publicMetadata': publicMetadata,
      };

  /// Whether this person has the role, the permission, or both when both are given.
  /// With neither, true (someone is signed in; `InIDClient.has` is false when nobody is).
  bool has({String? role, String? permission}) {
    if (role != null && !roles.contains(role)) return false;
    if (permission != null && !permissions.contains(permission)) return false;
    return true;
  }

  @override
  String toString() => 'InIDUser($id, ${name ?? email ?? phone ?? ''})';
}
