public import ISO_8824
public import ISO_8825

extension IETF.RFC.`5280` {
    /// `Name ::= CHOICE { rdnSequence RDNSequence }` with
    /// `RDNSequence ::= SEQUENCE OF RelativeDistinguishedName`
    /// (RFC 5280 §4.1.2.4).
    ///
    /// The CHOICE has exactly one arm, so `Name` is modeled directly as its
    /// RDN sequence. An empty sequence is the profile's *empty name* — legal
    /// for `subject` when a critical `subjectAltName` extension carries the
    /// identity (§4.2.1.6), and forbidden for `issuer`, which MUST contain a
    /// non-empty distinguished name (§4.1.2.4); that field-position law is
    /// enforced by certificate-level validation, not here.
    public struct Name: Hashable, Sendable {
        /// The relative distinguished names, from most to least significant
        /// (root first), in wire order.
        public var rdnSequence: [IETF.RFC.`5280`.RelativeDistinguishedName]

        public init(_ rdnSequence: [IETF.RFC.`5280`.RelativeDistinguishedName]) {
            self.rdnSequence = rdnSequence
        }
    }
}

extension IETF.RFC.`5280`.Name {
    /// Whether this is the empty name (an RDNSequence of length zero).
    public var isEmpty: Bool {
        self.rdnSequence.isEmpty
    }
}

extension IETF.RFC.`5280`.Name: ISO.`8825`.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO.`8824`.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO.`8825`.Node, withIdentifier identifier: ISO.`8824`.Identifier) throws(ISO.`8824`.Error) {
        self.rdnSequence = try ISO.`8825`.DER.sequence(
            of: IETF.RFC.`5280`.RelativeDistinguishedName.self,
            identifier: identifier,
            rootNode: node
        )
    }

    public func serialize(into coder: inout ISO.`8825`.DER.Serializer, withIdentifier identifier: ISO.`8824`.Identifier) throws(ISO.`8824`.Error) {
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO.`8825`.DER.Serializer) throws(ISO.`8824`.Error) in
            for rdn in self.rdnSequence {
                try coder.serialize(rdn)
            }
        }
    }
}
