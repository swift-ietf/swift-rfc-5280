// RFC_5280.PolicyMappings.swift
// RFC 5280 §4.2.1.5 — Policy Mappings
// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.5

public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
    /// issuerDomainPolicy CertPolicyId, subjectDomainPolicy CertPolicyId }`
    /// (RFC 5280 §4.2.1.5).
    ///
    /// Used in CA certificates to declare that the issuing CA considers one
    /// of its own policies equivalent to a policy in the subject CA's
    /// domain.
    ///
    /// Criticality law: conforming CAs SHOULD mark this extension as
    /// critical. Wire law: policies MUST NOT be mapped either to or from
    /// the special value `anyPolicy` (``isRFC5280Conformant``). Applying
    /// mappings during path validation is verifier runtime law.
    public struct PolicyMappings: Hashable, Sendable {
        /// The mapping terms, in wire order. Must contain at least one; the
        /// SIZE (1..MAX) bound is enforced at the wire boundary.
        public var mappings: [RFC_5280.PolicyMappings.Mapping]

        public init(_ mappings: [RFC_5280.PolicyMappings.Mapping]) {
            self.mappings = mappings
        }
    }
}

extension RFC_5280.PolicyMappings {
    /// Whether every mapping satisfies the §4.2.1.5 `anyPolicy`
    /// prohibition.
    public var isRFC5280Conformant: Bool {
        self.mappings.allSatisfy(\.isRFC5280Conformant)
    }
}

extension RFC_5280.PolicyMappings: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        let mappings = try ISO_8825.DER.sequence(
            of: RFC_5280.PolicyMappings.Mapping.self,
            identifier: identifier,
            rootNode: node
        )
        guard !mappings.isEmpty else {
            throw ISO_8824.Error.invalidASN1Object(
                reason: "PolicyMappings is SEQUENCE SIZE (1..MAX); got an empty sequence"
            )
        }
        self.mappings = mappings
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        guard !self.mappings.isEmpty else {
            throw ISO_8824.Error.invalidASN1Object(
                reason: "PolicyMappings is SEQUENCE SIZE (1..MAX); got an empty sequence"
            )
        }
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            for mapping in self.mappings {
                try coder.serialize(mapping)
            }
        }
    }
}

extension RFC_5280.PolicyMappings {
    /// `id-ce-policyMappings` (§4.2.1.5).
    public static var extensionID: ISO_8824.ObjectIdentifier {
        RFC_5280.Extension.ID.policyMappings
    }

    /// Decodes the typed value from a generic ``RFC_5280/Extension``.
    public init(_ certificateExtension: RFC_5280.Extension) throws(ISO_8824.Error) {
        guard certificateExtension.extnID == Self.extensionID else {
            throw ISO_8824.Error.invalidASN1Object(reason: "Expected id-ce-policyMappings, got \(certificateExtension.extnID)")
        }
        self = try Self(derEncoded: certificateExtension.extnValue.bytes)
    }

    /// Wraps this value as a generic ``RFC_5280/Extension``.
    ///
    /// §4.2.1.5 criticality law: conforming CAs SHOULD mark this extension
    /// critical, hence the default.
    public func makeExtension(critical: Bool = true) throws(ISO_8824.Error) -> RFC_5280.Extension {
        var serializer = ISO_8825.DER.Serializer()
        try serializer.serialize(self)
        return RFC_5280.Extension(
            extnID: Self.extensionID,
            critical: critical,
            extnValue: ISO_8824.OctetString(contentBytes: serializer.serializedBytes[...])
        )
    }
}
