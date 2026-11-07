public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `GeneralSubtree ::= SEQUENCE { base GeneralName, minimum [0]
    /// BaseDistance DEFAULT 0, maximum [1] BaseDistance OPTIONAL }` with
    /// `BaseDistance ::= INTEGER (0..MAX)` (RFC 5280 §4.2.1.10).
    ///
    /// Profile law: within this profile `minimum` MUST be zero and `maximum`
    /// MUST be absent — the fields exist for wire fidelity with the X.509
    /// syntax. `isRFC5280Conformant` reports the profile judgment.
    public struct GeneralSubtree: Hashable, Sendable {
        /// The subtree base name.
        public var base: RFC_5280.GeneralName

        /// The `minimum` base distance; the profile requires 0.
        public var minimum: Int

        /// The `maximum` base distance; the profile requires absence.
        public var maximum: Int?

        public init(base: RFC_5280.GeneralName, minimum: Int = 0, maximum: Int? = nil) {
            self.base = base
            self.minimum = minimum
            self.maximum = maximum
        }
    }
}

extension RFC_5280.GeneralSubtree {
    /// Whether this subtree satisfies the §4.2.1.10 profile law
    /// (`minimum` zero, `maximum` absent).
    public var isRFC5280Conformant: Bool {
        self.minimum == 0 && self.maximum == nil
    }
}

extension RFC_5280.GeneralSubtree: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        self = try ISO_8825.DER.sequence(node, identifier: identifier) { (nodes: inout ISO_8825.Node.Collection.Iterator) throws(ISO_8824.Error) -> Self in
            let base = try RFC_5280.GeneralName(derEncoded: &nodes)
            let minimum = try ISO_8825.DER.decodeDefault(
                &nodes,
                identifier: ISO_8824.Identifier(tagWithNumber: 0, tagClass: .contextSpecific),
                defaultValue: 0
            ) { (node: ISO_8825.Node) throws(ISO_8824.Error) -> Int in
                try Int(derEncoded: node, withIdentifier: ISO_8824.Identifier(tagWithNumber: 0, tagClass: .contextSpecific))
            }
            let maximum: Int? = try ISO_8825.DER.optionalImplicitlyTagged(
                &nodes,
                tag: ISO_8824.Identifier(tagWithNumber: 1, tagClass: .contextSpecific)
            )
            return Self(base: base, minimum: minimum, maximum: maximum)
        }
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            try coder.serialize(self.base)
            if self.minimum != 0 {
                try self.minimum.serialize(
                    into: &coder,
                    withIdentifier: ISO_8824.Identifier(tagWithNumber: 0, tagClass: .contextSpecific)
                )
            }
            try coder.serializeOptionalImplicitlyTagged(
                self.maximum,
                withIdentifier: ISO_8824.Identifier(tagWithNumber: 1, tagClass: .contextSpecific)
            )
        }
    }
}
