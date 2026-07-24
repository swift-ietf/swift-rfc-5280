// RFC_5280.CertificatePolicies.swift
// RFC 5280 §4.2.1.4 — Certificate Policies
// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.4

public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation`
    /// (RFC 5280 §4.2.1.4).
    ///
    /// Criticality law: conforming CAs SHOULD mark this extension as
    /// non-critical, but MAY mark it critical — in which case a
    /// certificate-using system MUST be able to process the extension,
    /// including the optional qualifiers, or MUST reject the certificate.
    ///
    /// Wire law: a certificate policy OID MUST NOT appear more than once in
    /// this extension (``hasDuplicatePolicies`` reports violations that
    /// survive parsing). Applying the policies to a certification path — the
    /// §6.1 valid-policy tree — is verifier runtime law, not wire law.
    public struct CertificatePolicies: Hashable, Sendable {
        /// The policy information terms, in wire order. Must contain at
        /// least one; the SIZE (1..MAX) bound is enforced at the wire
        /// boundary.
        public var policies: [RFC_5280.PolicyInformation]

        public init(_ policies: [RFC_5280.PolicyInformation]) {
            self.policies = policies
        }
    }
}

extension RFC_5280.CertificatePolicies {
    /// Whether any policy OID appears more than once, which §4.2.1.4
    /// forbids.
    public var hasDuplicatePolicies: Bool {
        var seen: Set<ISO_8824.ObjectIdentifier> = []
        for policy in self.policies where !seen.insert(policy.policyIdentifier).inserted {
            return true
        }
        return false
    }

    /// Whether the extension asserts ``RFC_5280/PolicyInformation/ID/anyPolicy``.
    public var assertsAnyPolicy: Bool {
        self.policies.contains { $0.isAnyPolicy }
    }

    /// Whether the extension satisfies the §4.2.1.4 rules that survive DER
    /// parsing: no policy OID repeats, and every qualifier is one of the two
    /// types the profile defines.
    ///
    /// This is the aggregate of ``hasDuplicatePolicies`` and each policy's
    /// ``RFC_5280/PolicyInformation/isRFC5280Conformant``.
    public var isRFC5280Conformant: Bool {
        !self.hasDuplicatePolicies && self.policies.allSatisfy(\.isRFC5280Conformant)
    }
}

extension RFC_5280.CertificatePolicies: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        let policies = try ISO_8825.DER.sequence(
            of: RFC_5280.PolicyInformation.self,
            identifier: identifier,
            rootNode: node
        )
        guard !policies.isEmpty else {
            throw ISO_8824.Error.invalidASN1Object(
                reason: "certificatePolicies is SEQUENCE SIZE (1..MAX) OF PolicyInformation; got an empty sequence"
            )
        }
        self.policies = policies
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        guard !self.policies.isEmpty else {
            throw ISO_8824.Error.invalidASN1Object(
                reason: "certificatePolicies is SEQUENCE SIZE (1..MAX) OF PolicyInformation; got an empty sequence"
            )
        }
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            for policy in self.policies {
                try coder.serialize(policy)
            }
        }
    }
}

extension RFC_5280.CertificatePolicies {
    /// `id-ce-certificatePolicies` (§4.2.1.4).
    public static var extensionID: ISO_8824.ObjectIdentifier {
        RFC_5280.Extension.ID.certificatePolicies
    }

    /// Decodes the typed value from a generic ``RFC_5280/Extension``.
    public init(_ certificateExtension: RFC_5280.Extension) throws(ISO_8824.Error) {
        guard certificateExtension.extnID == Self.extensionID else {
            throw ISO_8824.Error.invalidASN1Object(reason: "Expected id-ce-certificatePolicies, got \(certificateExtension.extnID)")
        }
        self = try Self(derEncoded: certificateExtension.extnValue.bytes)
    }

    /// Wraps this value as a generic ``RFC_5280/Extension``.
    ///
    /// §4.2.1.4 criticality law: conforming CAs SHOULD mark this extension
    /// non-critical, hence the default.
    public func makeExtension(critical: Bool = false) throws(ISO_8824.Error) -> RFC_5280.Extension {
        var serializer = ISO_8825.DER.Serializer()
        try serializer.serialize(self)
        return RFC_5280.Extension(
            extnID: Self.extensionID,
            critical: critical,
            extnValue: ISO_8824.OctetString(contentBytes: serializer.serializedBytes[...])
        )
    }
}
