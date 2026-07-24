// RFC_5280.PolicyInformation.swift
// RFC 5280 §4.2.1.4 — Certificate Policies: PolicyInformation
// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.4

public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `PolicyInformation ::= SEQUENCE { policyIdentifier CertPolicyId,
    /// policyQualifiers SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo
    /// OPTIONAL }` with `CertPolicyId ::= OBJECT IDENTIFIER`
    /// (RFC 5280 §4.2.1.4).
    ///
    /// Profile law: the special policy ``ID/anyPolicy`` asserts that the
    /// certificate may be used for any policy; a certificate policy OID
    /// MUST NOT appear more than once within one extension, and to promote
    /// interoperability CAs SHOULD identify policies by OID alone rather
    /// than by qualifier.
    public struct PolicyInformation: Hashable, Sendable {
        /// The policy OBJECT IDENTIFIER.
        public var policyIdentifier: ISO_8824.ObjectIdentifier

        /// The policy qualifiers (`nil` means the field is absent; when
        /// present it must hold at least one qualifier).
        public var policyQualifiers: [RFC_5280.PolicyQualifierInfo]?

        public init(
            policyIdentifier: ISO_8824.ObjectIdentifier,
            policyQualifiers: [RFC_5280.PolicyQualifierInfo]? = nil
        ) {
            self.policyIdentifier = policyIdentifier
            self.policyQualifiers = policyQualifiers
        }
    }
}

extension RFC_5280.PolicyInformation {
    /// Whether this is the ``ID/anyPolicy`` assertion.
    public var isAnyPolicy: Bool {
        self.policyIdentifier == RFC_5280.PolicyInformation.ID.anyPolicy
    }

    /// Whether every qualifier carried here is one of the two types the
    /// profile defines (§4.2.1.4) — see
    /// ``RFC_5280/PolicyQualifierInfo/isRFC5280Conformant``.
    ///
    /// Qualifiers of other types are preserved for wire fidelity; this
    /// reports their presence so a policy layer can act on it.
    public var isRFC5280Conformant: Bool {
        self.policyQualifiers?.allSatisfy(\.isRFC5280Conformant) ?? true
    }
}

extension RFC_5280.PolicyInformation: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        self = try ISO_8825.DER.sequence(node, identifier: identifier) { (nodes: inout ISO_8825.Node.Collection.Iterator) throws(ISO_8824.Error) -> Self in
            let policyIdentifier = try ISO_8824.ObjectIdentifier(derEncoded: &nodes)
            var policyQualifiers: [RFC_5280.PolicyQualifierInfo]?
            if let qualifiersNode = nodes.next() {
                let qualifiers = try ISO_8825.DER.sequence(
                    of: RFC_5280.PolicyQualifierInfo.self,
                    identifier: .sequence,
                    rootNode: qualifiersNode
                )
                guard !qualifiers.isEmpty else {
                    throw ISO_8824.Error.invalidASN1Object(
                        reason: "policyQualifiers is SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo; got an empty sequence"
                    )
                }
                policyQualifiers = qualifiers
            }
            return Self(policyIdentifier: policyIdentifier, policyQualifiers: policyQualifiers)
        }
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            try coder.serialize(self.policyIdentifier)
            if let policyQualifiers = self.policyQualifiers {
                guard !policyQualifiers.isEmpty else {
                    throw ISO_8824.Error.invalidASN1Object(
                        reason: "policyQualifiers is SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo; got an empty sequence"
                    )
                }
                try coder.appendConstructedNode(identifier: .sequence) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
                    for qualifier in policyQualifiers {
                        try coder.serialize(qualifier)
                    }
                }
            }
        }
    }
}
