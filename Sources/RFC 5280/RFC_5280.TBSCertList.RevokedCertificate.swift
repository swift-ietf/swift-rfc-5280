public import ISO_8824
public import ISO_8825

extension RFC_5280.TBSCertList {
    /// One entry of `revokedCertificates SEQUENCE OF SEQUENCE {
    /// userCertificate CertificateSerialNumber, revocationDate Time,
    /// crlEntryExtensions Extensions OPTIONAL }` (RFC 5280 §5.1.2.6).
    ///
    /// The ASN.1 entry is an anonymous inner SEQUENCE, so it is named here
    /// for the nest rather than mirroring a spec token.
    ///
    /// Version law: if `crlEntryExtensions` is present, the CRL's version
    /// MUST be v2 — see ``RFC_5280/TBSCertList/minimumRequiredVersion``.
    /// The entry extensions themselves are §5.3 surfaces: `reasonCode`
    /// (``RFC_5280/CRLReason``), `invalidityDate`
    /// (``RFC_5280/InvalidityDate``) and `certificateIssuer`
    /// (``RFC_5280/CertificateIssuer``).
    public struct RevokedCertificate: Hashable, Sendable {
        /// The serial number of the revoked certificate.
        public var userCertificate: RFC_5280.Certificate.SerialNumber

        /// The date on which the revocation occurred.
        public var revocationDate: RFC_5280.Time

        /// The CRL entry extensions.
        ///
        /// `Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension`, so an empty
        /// array encodes as an absent field.
        public var crlEntryExtensions: [RFC_5280.Extension]

        public init(
            userCertificate: RFC_5280.Certificate.SerialNumber,
            revocationDate: RFC_5280.Time,
            crlEntryExtensions: [RFC_5280.Extension] = []
        ) {
            self.userCertificate = userCertificate
            self.revocationDate = revocationDate
            self.crlEntryExtensions = crlEntryExtensions
        }
    }
}

extension RFC_5280.TBSCertList.RevokedCertificate: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        self = try ISO_8825.DER.sequence(node, identifier: identifier) { (nodes: inout ISO_8825.Node.Collection.Iterator) throws(ISO_8824.Error) -> Self in
            let userCertificate = try RFC_5280.Certificate.SerialNumber(derEncoded: &nodes)
            let revocationDate = try RFC_5280.Time(derEncoded: &nodes)
            var crlEntryExtensions: [RFC_5280.Extension] = []
            if let extensionsNode = nodes.next() {
                crlEntryExtensions = try ISO_8825.DER.sequence(
                    of: RFC_5280.Extension.self,
                    identifier: .sequence,
                    rootNode: extensionsNode
                )
                guard !crlEntryExtensions.isEmpty else {
                    throw ISO_8824.Error.invalidASN1Object(
                        reason: "Extensions is SEQUENCE SIZE (1..MAX); an empty list must be encoded as an absent field"
                    )
                }
            }
            return Self(
                userCertificate: userCertificate,
                revocationDate: revocationDate,
                crlEntryExtensions: crlEntryExtensions
            )
        }
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            try coder.serialize(self.userCertificate)
            try coder.serialize(self.revocationDate)
            if !self.crlEntryExtensions.isEmpty {
                try coder.appendConstructedNode(identifier: .sequence) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
                    for entryExtension in self.crlEntryExtensions {
                        try coder.serialize(entryExtension)
                    }
                }
            }
        }
    }
}
