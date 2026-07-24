// RFC_5280.AccessDescription.ID.swift
// RFC 5280 §4.2.2.1 — Authority Information Access: access methods
// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.2.1

public import ISO_8824

extension RFC_5280.AccessDescription {
    /// The access methods assigned by RFC 5280 §4.2.2.1.
    ///
    /// The `id-ad` arc is `1.3.6.1.5.5.7.48`.
    public enum ID {}
}

extension RFC_5280.AccessDescription.ID {
    /// `id-ad-ocsp OBJECT IDENTIFIER ::= { id-ad 1 }` — the OCSP responder
    /// for this certificate; the location is a URI.
    public static let ocsp: ISO_8824.ObjectIdentifier = [1, 3, 6, 1, 5, 5, 7, 48, 1]

    /// `id-ad-caIssuers OBJECT IDENTIFIER ::= { id-ad 2 }` — where
    /// certificates issued to this certificate's issuer may be obtained.
    public static let caIssuers: ISO_8824.ObjectIdentifier = [1, 3, 6, 1, 5, 5, 7, 48, 2]
}
