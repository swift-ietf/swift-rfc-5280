// RFC_5280.PolicyConstraints.swift
// RFC 5280 §4.2.1.11 — Policy Constraints
// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.11

public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `PolicyConstraints ::= SEQUENCE { requireExplicitPolicy [0] SkipCerts
    /// OPTIONAL, inhibitPolicyMapping [1] SkipCerts OPTIONAL }` with
    /// `SkipCerts ::= INTEGER (0..MAX)` (RFC 5280 §4.2.1.11).
    ///
    /// Used in CA certificates to constrain path validation two ways:
    /// `requireExplicitPolicy` gives the number of additional certificates
    /// that may appear before an explicit policy is required for the whole
    /// path, and `inhibitPolicyMapping` the number before policy mapping is
    /// no longer permitted.
    ///
    /// Criticality law: conforming CAs MUST mark this extension as critical.
    /// Wire law: conforming CAs MUST NOT issue certificates where this
    /// extension is an empty sequence — at least one of the two fields MUST
    /// be present, which is enforced at the wire boundary. Both fields are
    /// implicitly tagged: `SkipCerts` is an INTEGER, not a CHOICE.
    public struct PolicyConstraints: Hashable, Sendable {
        /// Additional certificates that may appear before an explicit policy
        /// is required (`nil` means the field is absent).
        public var requireExplicitPolicy: Int?

        /// Additional certificates that may appear before policy mapping is
        /// no longer permitted (`nil` means the field is absent).
        public var inhibitPolicyMapping: Int?

        public init(requireExplicitPolicy: Int? = nil, inhibitPolicyMapping: Int? = nil) {
            self.requireExplicitPolicy = requireExplicitPolicy
            self.inhibitPolicyMapping = inhibitPolicyMapping
        }
    }
}

extension RFC_5280.PolicyConstraints: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        self = try ISO_8825.DER.sequence(node, identifier: identifier) { (nodes: inout ISO_8825.Node.Collection.Iterator) throws(ISO_8824.Error) -> Self in
            let requireExplicitPolicy: Int? = try ISO_8825.DER.optionalImplicitlyTagged(
                &nodes,
                tag: ISO_8824.Identifier(tagWithNumber: 0, tagClass: .contextSpecific)
            )
            let inhibitPolicyMapping: Int? = try ISO_8825.DER.optionalImplicitlyTagged(
                &nodes,
                tag: ISO_8824.Identifier(tagWithNumber: 1, tagClass: .contextSpecific)
            )
            guard requireExplicitPolicy != nil || inhibitPolicyMapping != nil else {
                throw ISO_8824.Error.invalidASN1Object(
                    reason: "PolicyConstraints must contain at least one of requireExplicitPolicy and inhibitPolicyMapping"
                )
            }
            for skipCerts in [requireExplicitPolicy, inhibitPolicyMapping].compactMap({ $0 }) where skipCerts < 0 {
                throw ISO_8824.Error.invalidASN1Object(reason: "SkipCerts is INTEGER (0..MAX); got \(skipCerts)")
            }
            return Self(requireExplicitPolicy: requireExplicitPolicy, inhibitPolicyMapping: inhibitPolicyMapping)
        }
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        guard self.requireExplicitPolicy != nil || self.inhibitPolicyMapping != nil else {
            throw ISO_8824.Error.invalidASN1Object(
                reason: "PolicyConstraints must contain at least one of requireExplicitPolicy and inhibitPolicyMapping"
            )
        }
        for skipCerts in [self.requireExplicitPolicy, self.inhibitPolicyMapping].compactMap({ $0 }) where skipCerts < 0 {
            throw ISO_8824.Error.invalidASN1Object(reason: "SkipCerts is INTEGER (0..MAX); got \(skipCerts)")
        }
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            try coder.serializeOptionalImplicitlyTagged(
                self.requireExplicitPolicy,
                withIdentifier: ISO_8824.Identifier(tagWithNumber: 0, tagClass: .contextSpecific)
            )
            try coder.serializeOptionalImplicitlyTagged(
                self.inhibitPolicyMapping,
                withIdentifier: ISO_8824.Identifier(tagWithNumber: 1, tagClass: .contextSpecific)
            )
        }
    }
}

extension RFC_5280.PolicyConstraints {
    /// `id-ce-policyConstraints` (§4.2.1.11).
    public static var extensionID: ISO_8824.ObjectIdentifier {
        RFC_5280.Extension.ID.policyConstraints
    }

    /// Decodes the typed value from a generic ``RFC_5280/Extension``.
    public init(_ certificateExtension: RFC_5280.Extension) throws(ISO_8824.Error) {
        guard certificateExtension.extnID == Self.extensionID else {
            throw ISO_8824.Error.invalidASN1Object(reason: "Expected id-ce-policyConstraints, got \(certificateExtension.extnID)")
        }
        self = try Self(derEncoded: certificateExtension.extnValue.bytes)
    }

    /// Wraps this value as a generic ``RFC_5280/Extension``.
    ///
    /// §4.2.1.11 criticality law: conforming CAs MUST mark this extension
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
