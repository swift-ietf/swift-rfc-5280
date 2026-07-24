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
    ///
    /// **Equality is set equality, not positional.** A SET is unordered, so
    /// two RDNs holding the same attributes are the same RDN whichever order
    /// they were supplied or decoded in. This is not merely the ASN.1 reading:
    /// because DER canonicalises SET OF ordering on serialization, two
    /// differently-ordered values encode to byte-identical DER, and equality
    /// that disagreed with byte-identity would be wrong under any reading of
    /// the type. ``attributes`` still preserves the order it was given, so
    /// wire fidelity is unaffected — only comparison is order-independent.
    ///
    /// This matters beyond representation: distinguished-name matching is
    /// built on RDN equality, so order-dependent equality would let a
    /// `directoryName` name constraint fail to match a name it governs — and
    /// in `excludedSubtrees` a failed match admits a certificate that should
    /// have been excluded.
    public struct RelativeDistinguishedName: Sendable {
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

extension RFC_5280.RelativeDistinguishedName: Hashable {
    /// Set equality over the attributes — see the type's documentation for why
    /// positional equality would be wrong here.
    ///
    /// Compared as a multiset so that a malformed RDN carrying a duplicate
    /// attribute is not silently equated with one that does not.
    public static func == (lhs: Self, rhs: Self) -> Bool {
        guard lhs.attributes.count == rhs.attributes.count else { return false }
        var remaining: [RFC_5280.AttributeTypeAndValue: Int] = [:]
        for attribute in lhs.attributes {
            remaining[attribute, default: 0] += 1
        }
        for attribute in rhs.attributes {
            guard let count = remaining[attribute] else { return false }
            if count == 1 {
                remaining.removeValue(forKey: attribute)
            } else {
                remaining[attribute] = count - 1
            }
        }
        return remaining.isEmpty
    }

    /// Order-independent, so that equal values hash equally.
    public func hash(into hasher: inout Hasher) {
        var combined = 0
        for attribute in self.attributes {
            combined ^= attribute.hashValue
        }
        hasher.combine(combined)
        hasher.combine(self.attributes.count)
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
