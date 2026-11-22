public import ISO_8824
public import ISO_8825

extension IETF.RFC.`5280`.TBSCertList {
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
        public var userCertificate: IETF.RFC.`5280`.Certificate.SerialNumber

        /// The date on which the revocation occurred.
        public var revocationDate: IETF.RFC.`5280`.Time

        /// The CRL entry extensions.
        ///
        /// `Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension`, so an empty
        /// array encodes as an absent field.
        public var crlEntryExtensions: [IETF.RFC.`5280`.Extension]

        public init(
            userCertificate: IETF.RFC.`5280`.Certificate.SerialNumber,
            revocationDate: IETF.RFC.`5280`.Time,
            crlEntryExtensions: [IETF.RFC.`5280`.Extension] = []
        ) {
            self.userCertificate = userCertificate
            self.revocationDate = revocationDate
            self.crlEntryExtensions = crlEntryExtensions
        }
    }
}

extension IETF.RFC.`5280`.TBSCertList.RevokedCertificate: ISO.`8825`.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO.`8824`.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO.`8825`.Node, withIdentifier identifier: ISO.`8824`.Identifier) throws(ISO.`8824`.Error) {
        self = try ISO.`8825`.DER.sequence(node, identifier: identifier) { (nodes: inout ISO.`8825`.Node.Collection.Iterator) throws(ISO.`8824`.Error) -> Self in
            let userCertificate = try IETF.RFC.`5280`.Certificate.SerialNumber(derEncoded: &nodes)
            let revocationDate = try IETF.RFC.`5280`.Time(derEncoded: &nodes)
            var crlEntryExtensions: [IETF.RFC.`5280`.Extension] = []
            if let extensionsNode = nodes.next() {
                crlEntryExtensions = try ISO.`8825`.DER.sequence(
                    of: IETF.RFC.`5280`.Extension.self,
                    identifier: .sequence,
                    rootNode: extensionsNode
                )
                guard !crlEntryExtensions.isEmpty else {
                    throw ISO.`8824`.Error.invalidASN1Object(
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

    public func serialize(into coder: inout ISO.`8825`.DER.Serializer, withIdentifier identifier: ISO.`8824`.Identifier) throws(ISO.`8824`.Error) {
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO.`8825`.DER.Serializer) throws(ISO.`8824`.Error) in
            try coder.serialize(self.userCertificate)
            try coder.serialize(self.revocationDate)
            if !self.crlEntryExtensions.isEmpty {
                try coder.appendConstructedNode(identifier: .sequence) { (coder: inout ISO.`8825`.DER.Serializer) throws(ISO.`8824`.Error) in
                    for entryExtension in self.crlEntryExtensions {
                        try coder.serialize(entryExtension)
                    }
                }
            }
        }
    }
}
