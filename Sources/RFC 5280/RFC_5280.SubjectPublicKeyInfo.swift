public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier,
    /// subjectPublicKey BIT STRING }` (RFC 5280 §4.1.2.7).
    ///
    /// The BIT STRING carries the algorithm-specific key encoding opaquely;
    /// interpreting it (RFC 3279 / RFC 5480 key formats) is the concern of
    /// the cryptographic runtime layer, not of this profile-law type.
    public struct SubjectPublicKeyInfo: Hashable, Sendable {
        /// The algorithm this key is for, with its parameter law.
        public var algorithm: RFC_5280.AlgorithmIdentifier

        /// The encoded public key.
        public var subjectPublicKey: ISO_8824.BitString

        public init(algorithm: RFC_5280.AlgorithmIdentifier, subjectPublicKey: ISO_8824.BitString) {
            self.algorithm = algorithm
            self.subjectPublicKey = subjectPublicKey
        }
    }
}

extension RFC_5280.SubjectPublicKeyInfo: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        self = try ISO_8825.DER.sequence(node, identifier: identifier) { (nodes: inout ISO_8825.Node.Collection.Iterator) throws(ISO_8824.Error) -> Self in
            let algorithm = try RFC_5280.AlgorithmIdentifier(derEncoded: &nodes)
            let subjectPublicKey = try ISO_8824.BitString(derEncoded: &nodes)
            return Self(algorithm: algorithm, subjectPublicKey: subjectPublicKey)
        }
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            try coder.serialize(self.algorithm)
            try coder.serialize(self.subjectPublicKey)
        }
    }
}
