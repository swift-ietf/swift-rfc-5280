// RFC_5280.PolicyQualifierInfo.ID.swift
// RFC 5280 §4.2.1.4 — Certificate Policies: assigned policy qualifiers
// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.4

public import ISO_8824

extension RFC_5280.PolicyQualifierInfo {
    /// The policy qualifier identifiers assigned by RFC 5280 §4.2.1.4.
    ///
    /// The `id-qt` arc is `1.3.6.1.5.5.7.2`.
    public enum ID {}
}

extension RFC_5280.PolicyQualifierInfo.ID {
    /// `id-qt-cps OBJECT IDENTIFIER ::= { id-qt 1 }` — the qualifier is a
    /// pointer to the issuer's Certification Practice Statement.
    public static let cps: ISO_8824.ObjectIdentifier = [1, 3, 6, 1, 5, 5, 7, 2, 1]

    /// `id-qt-unotice OBJECT IDENTIFIER ::= { id-qt 2 }` — the qualifier is
    /// a ``RFC_5280/UserNotice`` for display to a relying party.
    public static let unotice: ISO_8824.ObjectIdentifier = [1, 3, 6, 1, 5, 5, 7, 2, 2]
}
