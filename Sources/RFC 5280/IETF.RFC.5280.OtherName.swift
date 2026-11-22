public import ISO_8824
public import ISO_8825

extension IETF.RFC.`5280` {
    /// `OtherName ::= SEQUENCE { type-id OBJECT IDENTIFIER,
    /// value [0] EXPLICIT ANY DEFINED BY type-id }` (RFC 5280 §4.2.1.6).
    public struct OtherName: Hashable, Sendable {
        /// The OBJECT IDENTIFIER naming the value's syntax.
        public var typeID: ISO.`8824`.ObjectIdentifier

        /// The type-defined value, exactly as encoded.
        public var value: ISO.`8825`.`Any`

        public init(typeID: ISO.`8824`.ObjectIdentifier, value: ISO.`8825`.`Any`) {
            self.typeID = typeID
            self.value = value
        }
    }
}

extension IETF.RFC.`5280`.OtherName: ISO.`8825`.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO.`8824`.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO.`8825`.Node, withIdentifier identifier: ISO.`8824`.Identifier) throws(ISO.`8824`.Error) {
        self = try ISO.`8825`.DER.sequence(node, identifier: identifier) { (nodes: inout ISO.`8825`.Node.Collection.Iterator) throws(ISO.`8824`.Error) -> Self in
            let typeID = try ISO.`8824`.ObjectIdentifier(derEncoded: &nodes)
            let value = try ISO.`8825`.DER.explicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) { node throws(ISO.`8824`.Error) in
                ISO.`8825`.`Any`(derEncoded: node)
            }
            return Self(typeID: typeID, value: value)
        }
    }

    public func serialize(into coder: inout ISO.`8825`.DER.Serializer, withIdentifier identifier: ISO.`8824`.Identifier) throws(ISO.`8824`.Error) {
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO.`8825`.DER.Serializer) throws(ISO.`8824`.Error) in
            try coder.serialize(self.typeID)
            try coder.serialize(self.value, explicitlyTaggedWithTagNumber: 0, tagClass: .contextSpecific)
        }
    }
}
