public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `Attribute ::= SEQUENCE { type AttributeType, values SET OF
    /// AttributeValue }` with `AttributeType ::= OBJECT IDENTIFIER` and
    /// `AttributeValue ::= ANY -- DEFINED BY AttributeType`
    /// (RFC 5280 Appendix A.1, used by §4.2.1.8).
    ///
    /// Unlike ``RFC_5280/AttributeTypeAndValue`` — one type with exactly one
    /// value, as used inside a distinguished name — this carries a SET of
    /// values for a single type. Each value's syntax is defined by its
    /// type, so values are preserved exactly as encoded.
    /// **Equality compares ``values`` as a set, not positionally** — a SET OF
    /// is unordered, and because DER canonicalises its ordering on
    /// serialization, two differently-ordered values encode to byte-identical
    /// DER. See ``RFC_5280/RelativeDistinguishedName`` for the same law stated
    /// at length.
    public struct Attribute: Sendable {
        /// The attribute type OBJECT IDENTIFIER.
        public var type: ISO_8824.ObjectIdentifier

        /// The attribute values, exactly as encoded, in parsed wire order.
        ///
        /// DER law: the SET OF elements are transmitted in ascending order
        /// of their encoded byte value; serialization applies that ordering
        /// regardless of the order given here, so a parsed value carries the
        /// canonical order rather than the order originally supplied.
        public var values: [ISO_8825.`Any`]

        public init(type: ISO_8824.ObjectIdentifier, values: [ISO_8825.`Any`]) {
            self.type = type
            self.values = values
        }
    }
}

extension RFC_5280.Attribute: Hashable {
    /// The type compares by identity; ``values`` compares as a multiset, since
    /// `SET OF` is unordered on the wire.
    public static func == (lhs: Self, rhs: Self) -> Bool {
        guard lhs.type == rhs.type, lhs.values.count == rhs.values.count else { return false }
        var remaining: [ISO_8825.`Any`: Int] = [:]
        for value in lhs.values {
            remaining[value, default: 0] += 1
        }
        for value in rhs.values {
            guard let count = remaining[value] else { return false }
            if count == 1 {
                remaining.removeValue(forKey: value)
            } else {
                remaining[value] = count - 1
            }
        }
        return remaining.isEmpty
    }

    /// Order-independent over ``values``, so that equal values hash equally.
    public func hash(into hasher: inout Hasher) {
        hasher.combine(self.type)
        var combined = 0
        for value in self.values {
            combined ^= value.hashValue
        }
        hasher.combine(combined)
        hasher.combine(self.values.count)
    }
}

extension RFC_5280.Attribute: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        self = try ISO_8825.DER.sequence(node, identifier: identifier) { (nodes: inout ISO_8825.Node.Collection.Iterator) throws(ISO_8824.Error) -> Self in
            let type = try ISO_8824.ObjectIdentifier(derEncoded: &nodes)
            guard let valuesNode = nodes.next() else {
                throw ISO_8824.Error.invalidASN1Object(reason: "Attribute is missing its values")
            }
            let values = try ISO_8825.DER.set(
                of: ISO_8825.`Any`.self,
                identifier: .set,
                rootNode: valuesNode
            )
            return Self(type: type, values: values)
        }
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            try coder.serialize(self.type)
            try coder.serializeSetOf(self.values, identifier: .set)
        }
    }
}
