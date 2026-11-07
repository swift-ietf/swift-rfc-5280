public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER,
    /// parameters ANY DEFINED BY algorithm OPTIONAL }` (RFC 5280 §4.1.1.2).
    ///
    /// Parameter law is defined per-algorithm by the profile family:
    /// - RSA PKCS#1 v1.5 signature algorithms (`sha256WithRSAEncryption` et
    ///   al., RFC 4055 §5) MUST carry an explicit ASN.1 `NULL` parameter.
    /// - ECDSA signature algorithms (`ecdsa-with-SHA256` et al., RFC 5480
    ///   §2.1.1 / RFC 5758 §3.2) MUST omit the parameters field entirely.
    ///
    /// This type preserves the wire distinction exactly: `parameters == nil`
    /// means the field was absent; an explicit `NULL` is carried as a non-nil
    /// ``ISO_8825/Any`` holding the NULL encoding. Equality is strict wire
    /// equality — the NULL-versus-absent normalization some verifiers apply
    /// for legacy RSA certificates is runtime policy, not wire law.
    public struct AlgorithmIdentifier: Hashable, Sendable {
        /// The OBJECT IDENTIFIER naming the algorithm.
        public var algorithm: ISO_8824.ObjectIdentifier

        /// The `ANY DEFINED BY algorithm` parameters, exactly as encoded,
        /// or `nil` when the field is absent from the wire.
        public var parameters: ISO_8825.`Any`?

        public init(algorithm: ISO_8824.ObjectIdentifier, parameters: ISO_8825.`Any`? = nil) {
            self.algorithm = algorithm
            self.parameters = parameters
        }
    }
}

extension RFC_5280.AlgorithmIdentifier: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        self = try ISO_8825.DER.sequence(node, identifier: identifier) { (nodes: inout ISO_8825.Node.Collection.Iterator) throws(ISO_8824.Error) -> Self in
            let algorithm = try ISO_8824.ObjectIdentifier(derEncoded: &nodes)
            let parameters = nodes.next().map { ISO_8825.`Any`(derEncoded: $0) }
            return Self(algorithm: algorithm, parameters: parameters)
        }
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            try coder.serialize(self.algorithm)
            if let parameters = self.parameters {
                try coder.serialize(parameters)
            }
        }
    }
}
