public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `DistributionPoint ::= SEQUENCE { distributionPoint [0]
    /// DistributionPointName OPTIONAL, reasons [1] ReasonFlags OPTIONAL,
    /// cRLIssuer [2] GeneralNames OPTIONAL }` (RFC 5280 §4.2.1.13).
    ///
    /// Tagging law: `distributionPoint` tags ``Name``, which is a CHOICE, so
    /// that field is explicitly tagged by ASN.1 rule; `reasons` and
    /// `cRLIssuer` tag non-CHOICE types and are implicit.
    ///
    /// Wire law: a `DistributionPoint` MUST NOT consist of only the
    /// `reasons` field — either `distributionPoint` or `cRLIssuer` MUST be
    /// present, which is enforced at the wire boundary. When
    /// ``distributionPoint`` is absent the CRL issuer's own name supplies
    /// the distribution point name.
    public struct DistributionPoint: Hashable, Sendable {
        /// Where the CRL may be obtained.
        public var distributionPoint: RFC_5280.DistributionPoint.Name?

        /// The revocation reasons this distribution point covers; absence
        /// means all reasons.
        public var reasons: RFC_5280.ReasonFlags?

        /// The CRL issuer, when it differs from the certificate issuer.
        public var cRLIssuer: [RFC_5280.GeneralName]?

        public init(
            distributionPoint: RFC_5280.DistributionPoint.Name? = nil,
            reasons: RFC_5280.ReasonFlags? = nil,
            cRLIssuer: [RFC_5280.GeneralName]? = nil
        ) {
            self.distributionPoint = distributionPoint
            self.reasons = reasons
            self.cRLIssuer = cRLIssuer
        }
    }
}

extension RFC_5280.DistributionPoint {
    /// Whether this distribution point satisfies the §4.2.1.13 profile
    /// rules that survive DER parsing.
    ///
    /// Two rules apply: conforming CAs SHOULD NOT use the
    /// `nameRelativeToCRLIssuer` form to specify a distribution point name,
    /// and `cRLIssuer`, when present, MUST contain only the distinguished
    /// name of the CRL issuer — that is, only `directoryName` entries.
    /// Values violating either are preserved for wire fidelity and reported
    /// here.
    public var isRFC5280Conformant: Bool {
        if case .nameRelativeToCRLIssuer = self.distributionPoint {
            return false
        }
        guard let cRLIssuer = self.cRLIssuer else { return true }
        return !cRLIssuer.isEmpty && cRLIssuer.allSatisfy { name in
            if case .directoryName = name { return true }
            return false
        }
    }
}

extension RFC_5280.DistributionPoint: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
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
            let reasons: RFC_5280.ReasonFlags? = try ISO_8825.DER.optionalImplicitlyTagged(
                &nodes,
                tag: ISO_8824.Identifier(tagWithNumber: 1, tagClass: .contextSpecific)
            )
            let cRLIssuer = try ISO_8825.DER.optionalImplicitlyTagged(
                &nodes,
                tagNumber: 2,
                tagClass: .contextSpecific
            ) { (node: ISO_8825.Node) throws(ISO_8824.Error) -> [RFC_5280.GeneralName] in
                try ISO_8825.DER.sequence(
                    of: RFC_5280.GeneralName.self,
                    identifier: ISO_8824.Identifier(tagWithNumber: 2, tagClass: .contextSpecific),
                    rootNode: node
                )
            }
            guard distributionPoint != nil || cRLIssuer != nil else {
                throw ISO_8824.Error.invalidASN1Object(
                    reason: "A DistributionPoint must contain distributionPoint or cRLIssuer; reasons alone is forbidden"
                )
            }
            guard cRLIssuer.map({ !$0.isEmpty }) ?? true else {
                throw ISO_8824.Error.invalidASN1Object(reason: "cRLIssuer is GeneralNames, SEQUENCE SIZE (1..MAX) OF GeneralName; got an empty sequence")
            }
            return Self(distributionPoint: distributionPoint, reasons: reasons, cRLIssuer: cRLIssuer)
        }
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        guard self.distributionPoint != nil || self.cRLIssuer != nil else {
            throw ISO_8824.Error.invalidASN1Object(
                reason: "A DistributionPoint must contain distributionPoint or cRLIssuer; reasons alone is forbidden"
            )
        }
        guard self.cRLIssuer.map({ !$0.isEmpty }) ?? true else {
            throw ISO_8824.Error.invalidASN1Object(reason: "cRLIssuer is GeneralNames, SEQUENCE SIZE (1..MAX) OF GeneralName; got an empty sequence")
        }
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            if let distributionPoint = self.distributionPoint {
                try coder.serialize(distributionPoint, explicitlyTaggedWithTagNumber: 0, tagClass: .contextSpecific)
            }
            try coder.serializeOptionalImplicitlyTagged(
                self.reasons,
                withIdentifier: ISO_8824.Identifier(tagWithNumber: 1, tagClass: .contextSpecific)
            )
            if let cRLIssuer = self.cRLIssuer {
                try coder.appendConstructedNode(
                    identifier: ISO_8824.Identifier(tagWithNumber: 2, tagClass: .contextSpecific)
                ) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
                    for name in cRLIssuer {
                        try coder.serialize(name)
                    }
                }
            }
        }
    }
}
