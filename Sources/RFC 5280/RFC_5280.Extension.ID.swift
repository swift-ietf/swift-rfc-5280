// RFC_5280.Extension.ID.swift
// RFC 5280 §4.2.1 — Standard Extensions: assigned identifiers
// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1

public import ISO_8824

extension RFC_5280.Extension {
    /// The extension identifiers assigned by RFC 5280 §4.2 for the standard
    /// certificate extensions this module implements.
    ///
    /// The `id-ce` arc is `2.5.29` (joint-iso-ccitt(2) ds(5) 29); the
    /// private-extension arc `id-pe` is `1.3.6.1.5.5.7.1`.
    public enum ID {}
}

extension RFC_5280.Extension.ID {
    /// `id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::= { id-ce 35 }` (§4.2.1.1).
    public static let authorityKeyIdentifier: ISO_8824.ObjectIdentifier = [2, 5, 29, 35]

    /// `id-ce-subjectKeyIdentifier OBJECT IDENTIFIER ::= { id-ce 14 }` (§4.2.1.2).
    public static let subjectKeyIdentifier: ISO_8824.ObjectIdentifier = [2, 5, 29, 14]

    /// `id-ce-keyUsage OBJECT IDENTIFIER ::= { id-ce 15 }` (§4.2.1.3).
    public static let keyUsage: ISO_8824.ObjectIdentifier = [2, 5, 29, 15]

    /// `id-ce-subjectAltName OBJECT IDENTIFIER ::= { id-ce 17 }` (§4.2.1.6).
    public static let subjectAlternativeName: ISO_8824.ObjectIdentifier = [2, 5, 29, 17]

    /// `id-ce-basicConstraints OBJECT IDENTIFIER ::= { id-ce 19 }` (§4.2.1.9).
    public static let basicConstraints: ISO_8824.ObjectIdentifier = [2, 5, 29, 19]

    /// `id-ce-nameConstraints OBJECT IDENTIFIER ::= { id-ce 30 }` (§4.2.1.10).
    public static let nameConstraints: ISO_8824.ObjectIdentifier = [2, 5, 29, 30]

    /// `id-ce-extKeyUsage OBJECT IDENTIFIER ::= { id-ce 37 }` (§4.2.1.12).
    public static let extendedKeyUsage: ISO_8824.ObjectIdentifier = [2, 5, 29, 37]

    /// `id-pe-authorityInfoAccess OBJECT IDENTIFIER ::= { id-pe 1 }` (§4.2.2.1).
    public static let authorityInformationAccess: ISO_8824.ObjectIdentifier = [1, 3, 6, 1, 5, 5, 7, 1, 1]
}
