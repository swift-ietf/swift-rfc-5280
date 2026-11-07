public import ISO_8824

extension RFC_5280.PolicyInformation {
    /// The special policy identifiers assigned by RFC 5280 §4.2.1.4.
    public enum ID {}
}

extension RFC_5280.PolicyInformation.ID {
    /// `anyPolicy OBJECT IDENTIFIER ::= { id-ce-certificatePolicies 0 }`
    /// (§4.2.1.4) — asserts no restriction on the certificate's policy set.
    public static let anyPolicy: ISO_8824.ObjectIdentifier = [2, 5, 29, 32, 0]
}
