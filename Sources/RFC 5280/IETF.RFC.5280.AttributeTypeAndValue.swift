public import ISO_8824
public import ISO_8825

extension IETF.RFC.`5280` {
    /// `AttributeTypeAndValue ::= SEQUENCE { type AttributeType,
    /// value AttributeValue }` where `AttributeType ::= OBJECT IDENTIFIER`
    /// and `AttributeValue ::= ANY -- DEFINED BY AttributeType`
    /// (RFC 5280 §4.1.2.4).
    ///
    /// The standard naming attributes (`ISO_8824.ObjectIdentifier.NameAttributes`)
    /// carry `DirectoryString` values; other attribute types define their own
    /// value syntax, so the value is preserved as ``ISO_8825/Any`` and
    /// ``directoryStringValue()`` offers the profile's typed view on demand.
    public struct AttributeTypeAndValue: Hashable, Sendable {
        /// The attribute type OBJECT IDENTIFIER.
        public var type: ISO.`8824`.ObjectIdentifier

        /// The attribute value, exactly as encoded.
        public var value: ISO.`8825`.`Any`

        public init(type: ISO.`8824`.ObjectIdentifier, value: ISO.`8825`.`Any`) {
            self.type = type
            self.value = value
        }
    }
}

extension IETF.RFC.`5280`.AttributeTypeAndValue {
    /// Interprets the value under the profile's `DirectoryString` syntax.
    ///
    /// Throws when the encoded value is not one of the five
    /// `DirectoryString` arms.
    public func directoryStringValue() throws(ISO.`8824`.Error) -> IETF.RFC.`5280`.DirectoryString {
        try IETF.RFC.`5280`.DirectoryString(asn1Any: self.value)
    }
}

extension IETF.RFC.`5280`.AttributeTypeAndValue: ISO.`8825`.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO.`8824`.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO.`8825`.Node, withIdentifier identifier: ISO.`8824`.Identifier) throws(ISO.`8824`.Error) {
        self = try ISO.`8825`.DER.sequence(node, identifier: identifier) { (nodes: inout ISO.`8825`.Node.Collection.Iterator) throws(ISO.`8824`.Error) -> Self in
            let type = try ISO.`8824`.ObjectIdentifier(derEncoded: &nodes)
            guard let valueNode = nodes.next() else {
                throw ISO.`8824`.Error.invalidASN1Object(reason: "AttributeTypeAndValue is missing its value")
            }
            return Self(type: type, value: ISO.`8825`.`Any`(derEncoded: valueNode))
        }
    }

    public func serialize(into coder: inout ISO.`8825`.DER.Serializer, withIdentifier identifier: ISO.`8824`.Identifier) throws(ISO.`8824`.Error) {
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO.`8825`.DER.Serializer) throws(ISO.`8824`.Error) in
            try coder.serialize(self.type)
            try coder.serialize(self.value)
        }
    }
}
