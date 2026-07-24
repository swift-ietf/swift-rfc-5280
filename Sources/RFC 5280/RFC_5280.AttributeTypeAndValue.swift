// RFC_5280.AttributeTypeAndValue.swift
// RFC 5280 §4.1.2.4 — Issuer: AttributeTypeAndValue
// https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.4

public import ISO_8824
public import ISO_8825

extension RFC_5280 {
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
        public var type: ISO_8824.ObjectIdentifier

        /// The attribute value, exactly as encoded.
        public var value: ISO_8825.`Any`

        public init(type: ISO_8824.ObjectIdentifier, value: ISO_8825.`Any`) {
            self.type = type
            self.value = value
        }

        /// Interprets the value under the profile's `DirectoryString` syntax.
        ///
        /// Throws when the encoded value is not one of the five
        /// `DirectoryString` arms.
        public func directoryStringValue() throws(ISO_8824.Error) -> RFC_5280.DirectoryString {
            try RFC_5280.DirectoryString(asn1Any: self.value)
        }
    }
}

extension RFC_5280.AttributeTypeAndValue: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        self = try ISO_8825.DER.sequence(node, identifier: identifier) { (nodes: inout ISO_8825.Node.Collection.Iterator) throws(ISO_8824.Error) -> Self in
            let type = try ISO_8824.ObjectIdentifier(derEncoded: &nodes)
            guard let valueNode = nodes.next() else {
                throw ISO_8824.Error.invalidASN1Object(reason: "AttributeTypeAndValue is missing its value")
            }
            return Self(type: type, value: ISO_8825.`Any`(derEncoded: valueNode))
        }
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            try coder.serialize(self.type)
            try coder.serialize(self.value)
        }
    }
}
