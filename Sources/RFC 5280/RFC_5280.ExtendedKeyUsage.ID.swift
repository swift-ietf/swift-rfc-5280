public import ISO_8824

extension RFC_5280.ExtendedKeyUsage {
    /// The key purposes assigned by RFC 5280 §4.2.1.12.
    ///
    /// The `id-kp` arc is `1.3.6.1.5.5.7.3`.
    public enum ID {}
}

extension RFC_5280.ExtendedKeyUsage.ID {
    /// `anyExtendedKeyUsage OBJECT IDENTIFIER ::= { id-ce-extKeyUsage 0 }`.
    public static let anyExtendedKeyUsage: ISO_8824.ObjectIdentifier = [2, 5, 29, 37, 0]

    /// `id-kp-serverAuth OBJECT IDENTIFIER ::= { id-kp 1 }` — TLS WWW server authentication.
    public static let serverAuth: ISO_8824.ObjectIdentifier = [1, 3, 6, 1, 5, 5, 7, 3, 1]

    /// `id-kp-clientAuth OBJECT IDENTIFIER ::= { id-kp 2 }` — TLS WWW client authentication.
    public static let clientAuth: ISO_8824.ObjectIdentifier = [1, 3, 6, 1, 5, 5, 7, 3, 2]

    /// `id-kp-codeSigning OBJECT IDENTIFIER ::= { id-kp 3 }` — signing of downloadable executable code.
    public static let codeSigning: ISO_8824.ObjectIdentifier = [1, 3, 6, 1, 5, 5, 7, 3, 3]

    /// `id-kp-emailProtection OBJECT IDENTIFIER ::= { id-kp 4 }` — email protection.
    public static let emailProtection: ISO_8824.ObjectIdentifier = [1, 3, 6, 1, 5, 5, 7, 3, 4]

    /// `id-kp-timeStamping OBJECT IDENTIFIER ::= { id-kp 8 }` — binding the hash of an object to a time.
    public static let timeStamping: ISO_8824.ObjectIdentifier = [1, 3, 6, 1, 5, 5, 7, 3, 8]

    /// `id-kp-OCSPSigning OBJECT IDENTIFIER ::= { id-kp 9 }` — signing OCSP responses.
    public static let ocspSigning: ISO_8824.ObjectIdentifier = [1, 3, 6, 1, 5, 5, 7, 3, 9]
}
