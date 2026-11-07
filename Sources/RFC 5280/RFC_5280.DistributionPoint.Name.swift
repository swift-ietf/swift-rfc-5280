public import ISO_8824
public import ISO_8825

extension RFC_5280.DistributionPoint {
    /// `DistributionPointName ::= CHOICE { fullName [0] GeneralNames,
    /// nameRelativeToCRLIssuer [1] RelativeDistinguishedName }`
    /// (RFC 5280 §4.2.1.13, Appendix A.1 — IMPLICIT TAGS).
    ///
    /// Tagging law: both arms tag a non-CHOICE type (a SEQUENCE OF and a
    /// SET OF respectively), so both context tags are implicit. The
    /// enclosing `distributionPoint [0]` field, by contrast, tags this
    /// CHOICE and is therefore explicit — see ``RFC_5280/DistributionPoint``.
    ///
    /// Profile law: when ``fullName(_:)`` is used the name SHOULD contain a
    /// URI; ``nameRelativeToCRLIssuer(_:)`` is relative to the CRL issuer's
    /// name and conforming CAs SHOULD NOT use it.
    public enum Name: Hashable, Sendable {
        case fullName([RFC_5280.GeneralName])
        case nameRelativeToCRLIssuer(RFC_5280.RelativeDistinguishedName)
    }
}

extension RFC_5280.DistributionPoint.Name: ISO_8825.DER.Parseable, ISO_8825.DER.Serializable {
    public init(derEncoded node: ISO_8825.Node) throws(ISO_8824.Error) {
        guard node.identifier.tagClass == .contextSpecific else {
            throw ISO_8824.Error.unexpectedFieldType(node.identifier)
        }

        switch node.identifier.tagNumber {
        case 0:
            let names = try ISO_8825.DER.sequence(
                of: RFC_5280.GeneralName.self,
                identifier: ISO_8824.Identifier(tagWithNumber: 0, tagClass: .contextSpecific),
                rootNode: node
            )
            guard !names.isEmpty else {
                throw ISO_8824.Error.invalidASN1Object(
                    reason: "GeneralNames is SEQUENCE SIZE (1..MAX) OF GeneralName; got an empty sequence"
                )
            }
            self = .fullName(names)
        case 1:
            self = .nameRelativeToCRLIssuer(
                try RFC_5280.RelativeDistinguishedName(
                    derEncoded: node,
                    withIdentifier: ISO_8824.Identifier(tagWithNumber: 1, tagClass: .contextSpecific)
                )
            )
        default:
            throw ISO_8824.Error.unexpectedFieldType(node.identifier)
        }
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) {
        switch self {
        case .fullName(let names):
            guard !names.isEmpty else {
                throw ISO_8824.Error.invalidASN1Object(
                    reason: "GeneralNames is SEQUENCE SIZE (1..MAX) OF GeneralName; got an empty sequence"
                )
            }
            try coder.appendConstructedNode(
                identifier: ISO_8824.Identifier(tagWithNumber: 0, tagClass: .contextSpecific)
            ) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
                for name in names {
                    try coder.serialize(name)
                }
            }
        case .nameRelativeToCRLIssuer(let rdn):
            try rdn.serialize(
                into: &coder,
                withIdentifier: ISO_8824.Identifier(tagWithNumber: 1, tagClass: .contextSpecific)
            )
        }
    }
}
