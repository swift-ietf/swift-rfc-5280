// RFC_5280.PolicyMappings.Mapping.swift
// RFC 5280 §4.2.1.5 — Policy Mappings: one mapping term
// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.5

public import ISO_8824
public import ISO_8825

extension RFC_5280.PolicyMappings {
    /// One term of `PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
    /// issuerDomainPolicy CertPolicyId, subjectDomainPolicy CertPolicyId }`
    /// (RFC 5280 §4.2.1.5).
    ///
    /// The ASN.1 term is an anonymous inner SEQUENCE, so it is named here
    /// for the nest rather than mirroring a spec token.
    ///
    /// Profile law: policies MUST NOT be mapped either to or from the
    /// special value `anyPolicy` (``isRFC5280Conformant``).
    public struct Mapping: Hashable, Sendable {
        /// A policy of the issuer's domain.
        public var issuerDomainPolicy: ISO_8824.ObjectIdentifier

        /// The subject-domain policy it is considered equivalent to.
        public var subjectDomainPolicy: ISO_8824.ObjectIdentifier

        public init(
            issuerDomainPolicy: ISO_8824.ObjectIdentifier,
            subjectDomainPolicy: ISO_8824.ObjectIdentifier
        ) {
            self.issuerDomainPolicy = issuerDomainPolicy
            self.subjectDomainPolicy = subjectDomainPolicy
        }
    }
}

extension RFC_5280.PolicyMappings.Mapping {
    /// Whether the mapping satisfies the §4.2.1.5 prohibition on mapping
    /// to or from `anyPolicy`.
    public var isRFC5280Conformant: Bool {
        let anyPolicy = RFC_5280.PolicyInformation.ID.anyPolicy
        return self.issuerDomainPolicy != anyPolicy && self.subjectDomainPolicy != anyPolicy
    }
}

extension RFC_5280.PolicyMappings.Mapping: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        self = try ISO_8825.DER.sequence(node, identifier: identifier) { (nodes: inout ISO_8825.Node.Collection.Iterator) throws(ISO_8824.Error) -> Self in
            let issuerDomainPolicy = try ISO_8824.ObjectIdentifier(derEncoded: &nodes)
            let subjectDomainPolicy = try ISO_8824.ObjectIdentifier(derEncoded: &nodes)
            return Self(issuerDomainPolicy: issuerDomainPolicy, subjectDomainPolicy: subjectDomainPolicy)
        }
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            try coder.serialize(self.issuerDomainPolicy)
            try coder.serialize(self.subjectDomainPolicy)
        }
    }
}
