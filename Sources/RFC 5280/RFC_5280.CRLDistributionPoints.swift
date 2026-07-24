// RFC_5280.CRLDistributionPoints.swift
// RFC 5280 §4.2.1.13 — CRL Distribution Points
// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13

public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF
    /// DistributionPoint` (RFC 5280 §4.2.1.13).
    ///
    /// Identifies how CRL information is obtained for the certificate.
    ///
    /// Criticality law: the extension SHOULD be non-critical, but CAs are
    /// encouraged to include it — support for it is strongly recommended
    /// for CAs and applications. Retrieving and checking the CRL is
    /// verifier runtime law; this type carries the pointer's wire law only.
    public struct CRLDistributionPoints: Hashable, Sendable {
        /// The distribution points, in wire order. Must contain at least
        /// one; the SIZE (1..MAX) bound is enforced at the wire boundary.
        public var distributionPoints: [RFC_5280.DistributionPoint]

        public init(_ distributionPoints: [RFC_5280.DistributionPoint]) {
            self.distributionPoints = distributionPoints
        }
    }
}

extension RFC_5280.CRLDistributionPoints {
    /// Whether every distribution point satisfies the §4.2.1.13 profile
    /// rules — see ``RFC_5280/DistributionPoint/isRFC5280Conformant``.
    public var isRFC5280Conformant: Bool {
        self.distributionPoints.allSatisfy(\.isRFC5280Conformant)
    }
}

extension RFC_5280.CRLDistributionPoints: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        let distributionPoints = try ISO_8825.DER.sequence(
            of: RFC_5280.DistributionPoint.self,
            identifier: identifier,
            rootNode: node
        )
        guard !distributionPoints.isEmpty else {
            throw ISO_8824.Error.invalidASN1Object(
                reason: "CRLDistributionPoints is SEQUENCE SIZE (1..MAX) OF DistributionPoint; got an empty sequence"
            )
        }
        self.distributionPoints = distributionPoints
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        guard !self.distributionPoints.isEmpty else {
            throw ISO_8824.Error.invalidASN1Object(
                reason: "CRLDistributionPoints is SEQUENCE SIZE (1..MAX) OF DistributionPoint; got an empty sequence"
            )
        }
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            for distributionPoint in self.distributionPoints {
                try coder.serialize(distributionPoint)
            }
        }
    }
}

extension RFC_5280.CRLDistributionPoints {
    /// `id-ce-cRLDistributionPoints` (§4.2.1.13).
    public static var extensionID: ISO_8824.ObjectIdentifier {
        RFC_5280.Extension.ID.cRLDistributionPoints
    }

    /// Decodes the typed value from a generic ``RFC_5280/Extension``.
    public init(_ certificateExtension: RFC_5280.Extension) throws(ISO_8824.Error) {
        guard certificateExtension.extnID == Self.extensionID else {
            throw ISO_8824.Error.invalidASN1Object(reason: "Expected id-ce-cRLDistributionPoints, got \(certificateExtension.extnID)")
        }
        self = try Self(derEncoded: certificateExtension.extnValue.bytes)
    }

    /// Wraps this value as a generic ``RFC_5280/Extension``.
    ///
    /// §4.2.1.13 criticality law: the extension SHOULD be non-critical,
    /// hence the default.
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
