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

    /// `id-ce-certificatePolicies OBJECT IDENTIFIER ::= { id-ce 32 }` (§4.2.1.4).
    public static let certificatePolicies: ISO_8824.ObjectIdentifier = [2, 5, 29, 32]

    /// `id-ce-policyMappings OBJECT IDENTIFIER ::= { id-ce 33 }` (§4.2.1.5).
    public static let policyMappings: ISO_8824.ObjectIdentifier = [2, 5, 29, 33]

    /// `id-ce-subjectAltName OBJECT IDENTIFIER ::= { id-ce 17 }` (§4.2.1.6).
    public static let subjectAlternativeName: ISO_8824.ObjectIdentifier = [2, 5, 29, 17]

    /// `id-ce-issuerAltName OBJECT IDENTIFIER ::= { id-ce 18 }` (§4.2.1.7).
    public static let issuerAlternativeName: ISO_8824.ObjectIdentifier = [2, 5, 29, 18]

    /// `id-ce-subjectDirectoryAttributes OBJECT IDENTIFIER ::= { id-ce 9 }` (§4.2.1.8).
    public static let subjectDirectoryAttributes: ISO_8824.ObjectIdentifier = [2, 5, 29, 9]

    /// `id-ce-basicConstraints OBJECT IDENTIFIER ::= { id-ce 19 }` (§4.2.1.9).
    public static let basicConstraints: ISO_8824.ObjectIdentifier = [2, 5, 29, 19]

    /// `id-ce-nameConstraints OBJECT IDENTIFIER ::= { id-ce 30 }` (§4.2.1.10).
    public static let nameConstraints: ISO_8824.ObjectIdentifier = [2, 5, 29, 30]

    /// `id-ce-policyConstraints OBJECT IDENTIFIER ::= { id-ce 36 }` (§4.2.1.11).
    public static let policyConstraints: ISO_8824.ObjectIdentifier = [2, 5, 29, 36]

    /// `id-ce-extKeyUsage OBJECT IDENTIFIER ::= { id-ce 37 }` (§4.2.1.12).
    public static let extendedKeyUsage: ISO_8824.ObjectIdentifier = [2, 5, 29, 37]

    /// `id-ce-cRLDistributionPoints OBJECT IDENTIFIER ::= { id-ce 31 }` (§4.2.1.13).
    public static let cRLDistributionPoints: ISO_8824.ObjectIdentifier = [2, 5, 29, 31]

    /// `id-ce-inhibitAnyPolicy OBJECT IDENTIFIER ::= { id-ce 54 }` (§4.2.1.14).
    public static let inhibitAnyPolicy: ISO_8824.ObjectIdentifier = [2, 5, 29, 54]

    /// `id-ce-freshestCRL OBJECT IDENTIFIER ::= { id-ce 46 }` (§4.2.1.15).
    public static let freshestCRL: ISO_8824.ObjectIdentifier = [2, 5, 29, 46]

    /// `id-pe-authorityInfoAccess OBJECT IDENTIFIER ::= { id-pe 1 }` (§4.2.2.1).
    public static let authorityInformationAccess: ISO_8824.ObjectIdentifier = [1, 3, 6, 1, 5, 5, 7, 1, 1]
}
