// RFC_5280.RelativeDistinguishedName.swift
// RFC 5280 §4.1.2.4 — Issuer: RelativeDistinguishedName
// https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.4

public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `RelativeDistinguishedName ::= SET SIZE (1..MAX) OF
    /// AttributeTypeAndValue` (RFC 5280 §4.1.2.4).
    ///
    /// DER law: the SET OF elements are ordered by their encoded byte value
    /// on the wire; serialization applies that ordering regardless of the
    /// order of ``attributes``. Multi-valued RDNs are legal but rare — most
    /// RDNs hold exactly one attribute.
    public struct RelativeDistinguishedName: Hashable, Sendable {
        /// The attributes in this RDN, in parsed wire order.
        ///
        /// Must contain at least one attribute to serialize a conformant RDN;
        /// the SIZE (1..MAX) bound is enforced at the wire boundary.
        public var attributes: [RFC_5280.AttributeTypeAndValue]

        public init(_ attributes: [RFC_5280.AttributeTypeAndValue]) {
            self.attributes = attributes
        }
    }
}

extension RFC_5280.RelativeDistinguishedName: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        .set
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        let attributes = try ISO_8825.DER.set(
            of: RFC_5280.AttributeTypeAndValue.self,
            identifier: identifier,
            rootNode: node
        )
        guard !attributes.isEmpty else {
            throw ISO_8824.Error.invalidASN1Object(reason: "RelativeDistinguishedName must contain at least one attribute")
        }
        self.attributes = attributes
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        guard !self.attributes.isEmpty else {
            throw ISO_8824.Error.invalidASN1Object(reason: "RelativeDistinguishedName must contain at least one attribute")
        }
        try coder.serializeSetOf(self.attributes, identifier: identifier)
    }
}
