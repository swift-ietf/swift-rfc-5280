public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `IssuingDistributionPoint ::= SEQUENCE { distributionPoint [0]
    /// DistributionPointName OPTIONAL, onlyContainsUserCerts [1] BOOLEAN
    /// DEFAULT FALSE, onlyContainsCACerts [2] BOOLEAN DEFAULT FALSE,
    /// onlySomeReasons [3] ReasonFlags OPTIONAL, indirectCRL [4] BOOLEAN
    /// DEFAULT FALSE, onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE }`
    /// (RFC 5280 §5.2.5).
    ///
    /// Names the distribution point for a CRL and states what the CRL
    /// covers. A relying party must match this against the
    /// ``RFC_5280/DistributionPoint`` it followed from the certificate.
    ///
    /// Tagging law: `distributionPoint [0]` tags ``RFC_5280/DistributionPoint/Name``,
    /// which is a CHOICE, so it is explicitly tagged; every other field
    /// tags a non-CHOICE type and is implicit.
    ///
    /// Criticality law: conforming CAs MUST mark this extension as critical
    /// — its scope limits are not safely ignorable. Wire law: at most one of
    /// `onlyContainsUserCerts`, `onlyContainsCACerts`, and
    /// `onlyContainsAttributeCerts` may be TRUE
    /// (``isRFC5280Conformant``).
    public struct IssuingDistributionPoint: Hashable, Sendable {
        /// The distribution point name this CRL is issued under.
        public var distributionPoint: RFC_5280.DistributionPoint.Name?

        /// Whether the CRL covers only end-entity certificates.
        public var onlyContainsUserCerts: Bool

        /// Whether the CRL covers only CA certificates.
        public var onlyContainsCACerts: Bool

        /// The revocation reasons the CRL covers; absence means all reasons.
        public var onlySomeReasons: RFC_5280.ReasonFlags?

        /// Whether the CRL is an indirect CRL, carrying revocations for
        /// certificates issued by other authorities.
        public var indirectCRL: Bool

        /// Whether the CRL covers only attribute certificates.
        public var onlyContainsAttributeCerts: Bool

        public init(
            distributionPoint: RFC_5280.DistributionPoint.Name? = nil,
            onlyContainsUserCerts: Bool = false,
            onlyContainsCACerts: Bool = false,
            onlySomeReasons: RFC_5280.ReasonFlags? = nil,
            indirectCRL: Bool = false,
            onlyContainsAttributeCerts: Bool = false
        ) {
            self.distributionPoint = distributionPoint
            self.onlyContainsUserCerts = onlyContainsUserCerts
            self.onlyContainsCACerts = onlyContainsCACerts
            self.onlySomeReasons = onlySomeReasons
            self.indirectCRL = indirectCRL
            self.onlyContainsAttributeCerts = onlyContainsAttributeCerts
        }
    }
}

extension RFC_5280.IssuingDistributionPoint {
    /// Whether the scope flags satisfy §5.2.5: at most one of
    /// `onlyContainsUserCerts`, `onlyContainsCACerts`, and
    /// `onlyContainsAttributeCerts` may be TRUE.
    ///
    /// Values violating this are preserved for wire fidelity and reported
    /// here.
    public var isRFC5280Conformant: Bool {
        let exclusive = [
            self.onlyContainsUserCerts,
            self.onlyContainsCACerts,
            self.onlyContainsAttributeCerts,
        ]
        return exclusive.filter { $0 }.count <= 1
    }
}

extension RFC_5280.IssuingDistributionPoint: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    /// Decodes one `[n] IMPLICIT BOOLEAN DEFAULT FALSE` field.
    ///
    /// `Bool` decodes against whichever identifier it is given, so the
    /// context tag has to be threaded through the builder rather than left
    /// to the type's own `BOOLEAN` identifier.
    private static func decodeTaggedDefault(
        _ nodes: inout ISO_8825.Node.Collection.Iterator,
        tagNumber: UInt
    ) throws(ISO_8824.Error) -> Bool {
        let tag = ISO_8824.Identifier(tagWithNumber: tagNumber, tagClass: .contextSpecific)
        return try ISO_8825.DER.decodeDefault(&nodes, identifier: tag, defaultValue: false) { node throws(ISO_8824.Error) in
            try Bool(derEncoded: node, withIdentifier: tag)
        }
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        self = try ISO_8825.DER.sequence(node, identifier: identifier) { (nodes: inout ISO_8825.Node.Collection.Iterator) throws(ISO_8824.Error) -> Self in
            let distributionPoint = try ISO_8825.DER.optionalExplicitlyTagged(
                &nodes,
                tagNumber: 0,
                tagClass: .contextSpecific
            ) { node throws(ISO_8824.Error) in
                try RFC_5280.DistributionPoint.Name(derEncoded: node)
            }
            let onlyContainsUserCerts = try Self.decodeTaggedDefault(&nodes, tagNumber: 1)
            let onlyContainsCACerts = try Self.decodeTaggedDefault(&nodes, tagNumber: 2)
            let onlySomeReasons: RFC_5280.ReasonFlags? = try ISO_8825.DER.optionalImplicitlyTagged(
                &nodes,
                tag: ISO_8824.Identifier(tagWithNumber: 3, tagClass: .contextSpecific)
            )
            let indirectCRL = try Self.decodeTaggedDefault(&nodes, tagNumber: 4)
            let onlyContainsAttributeCerts = try Self.decodeTaggedDefault(&nodes, tagNumber: 5)
            return Self(
                distributionPoint: distributionPoint,
                onlyContainsUserCerts: onlyContainsUserCerts,
                onlyContainsCACerts: onlyContainsCACerts,
                onlySomeReasons: onlySomeReasons,
                indirectCRL: indirectCRL,
                onlyContainsAttributeCerts: onlyContainsAttributeCerts
            )
        }
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            if let distributionPoint = self.distributionPoint {
                try coder.serialize(distributionPoint, explicitlyTaggedWithTagNumber: 0, tagClass: .contextSpecific)
            }
            if self.onlyContainsUserCerts {
                try true.serialize(into: &coder, withIdentifier: ISO_8824.Identifier(tagWithNumber: 1, tagClass: .contextSpecific))
            }
            if self.onlyContainsCACerts {
                try true.serialize(into: &coder, withIdentifier: ISO_8824.Identifier(tagWithNumber: 2, tagClass: .contextSpecific))
            }
            try coder.serializeOptionalImplicitlyTagged(
                self.onlySomeReasons,
                withIdentifier: ISO_8824.Identifier(tagWithNumber: 3, tagClass: .contextSpecific)
            )
            if self.indirectCRL {
                try true.serialize(into: &coder, withIdentifier: ISO_8824.Identifier(tagWithNumber: 4, tagClass: .contextSpecific))
            }
            if self.onlyContainsAttributeCerts {
                try true.serialize(into: &coder, withIdentifier: ISO_8824.Identifier(tagWithNumber: 5, tagClass: .contextSpecific))
            }
        }
    }
}

extension RFC_5280.IssuingDistributionPoint {
    /// `id-ce-issuingDistributionPoint` (§5.2.5).
    public static var extensionID: ISO_8824.ObjectIdentifier {
        RFC_5280.Extension.ID.issuingDistributionPoint
    }

    /// Decodes the typed value from a generic ``RFC_5280/Extension``.
    public init(_ certificateExtension: RFC_5280.Extension) throws(ISO_8824.Error) {
        guard certificateExtension.extnID == Self.extensionID else {
            throw ISO_8824.Error.invalidASN1Object(reason: "Expected id-ce-issuingDistributionPoint, got \(certificateExtension.extnID)")
        }
        self = try Self(derEncoded: certificateExtension.extnValue.bytes)
    }

    /// Wraps this value as a generic ``RFC_5280/Extension``.
    ///
    /// §5.2.5 criticality law: conforming CAs MUST mark this extension
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
