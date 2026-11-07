public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `TBSCertList ::= SEQUENCE { version Version OPTIONAL, signature
    /// AlgorithmIdentifier, issuer Name, thisUpdate Time, nextUpdate Time
    /// OPTIONAL, revokedCertificates SEQUENCE OF SEQUENCE { ... } OPTIONAL,
    /// crlExtensions [0] EXPLICIT Extensions OPTIONAL }`
    /// (RFC 5280 §5.1.1, §5.1.2).
    ///
    /// Version law (§5.1.2.1): if any extensions are present — CRL
    /// extensions or entry extensions — the version MUST be `v2`; otherwise
    /// the field MUST be absent, which this type models as `nil`. See
    /// ``minimumRequiredVersion``. Note that CRL versions stop at `v2`,
    /// unlike certificates, which reach `v3`.
    ///
    /// The `signature` field MUST contain the same algorithm identifier as
    /// the enclosing ``RFC_5280/CertificateList``'s `signatureAlgorithm`
    /// (§5.1.1.2) — a cross-structure law the CRL runtime enforces.
    /// Deciding whether a certificate is revoked is CRL-processing runtime
    /// law; this type carries the list's wire law only.
    public struct TBSCertList: Hashable, Sendable {
        /// The CRL version; `nil` when the field is absent, which the
        /// profile requires for a v1 CRL.
        public var version: RFC_5280.Certificate.Version?

        /// The algorithm used to sign this CRL.
        public var signature: RFC_5280.AlgorithmIdentifier

        /// The CRL issuer. §5.1.2.3 requires a non-empty distinguished name.
        public var issuer: RFC_5280.Name

        /// The issue date of this CRL.
        public var thisUpdate: RFC_5280.Time

        /// The date by which the next CRL will be issued.
        public var nextUpdate: RFC_5280.Time?

        /// The revoked certificates. An empty array encodes as an absent
        /// field, which is how a CRL with no revocations is expressed.
        public var revokedCertificates: [RFC_5280.TBSCertList.RevokedCertificate]

        /// The CRL extensions (§5.2).
        ///
        /// `Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension`, so an empty
        /// array encodes as an absent `[0]` field.
        public var crlExtensions: [RFC_5280.Extension]

        public init(
            version: RFC_5280.Certificate.Version? = nil,
            signature: RFC_5280.AlgorithmIdentifier,
            issuer: RFC_5280.Name,
            thisUpdate: RFC_5280.Time,
            nextUpdate: RFC_5280.Time? = nil,
            revokedCertificates: [RFC_5280.TBSCertList.RevokedCertificate] = [],
            crlExtensions: [RFC_5280.Extension] = []
        ) {
            self.version = version
            self.signature = signature
            self.issuer = issuer
            self.thisUpdate = thisUpdate
            self.nextUpdate = nextUpdate
            self.revokedCertificates = revokedCertificates
            self.crlExtensions = crlExtensions
        }
    }
}

extension RFC_5280.TBSCertList {
    /// The version §5.1.2.1 requires for this CRL's populated fields: `v2`
    /// when any CRL extension or entry extension is present, and otherwise
    /// `nil` — the field MUST be absent for a v1 CRL.
    public var minimumRequiredVersion: RFC_5280.Certificate.Version? {
        if !self.crlExtensions.isEmpty {
            return .v2
        }
        if self.revokedCertificates.contains(where: { !$0.crlEntryExtensions.isEmpty }) {
            return .v2
        }
        return nil
    }

    /// Whether ``version`` matches what §5.1.2.1 requires for the populated
    /// fields, and stays within the `v1`/`v2` range CRLs define.
    public var isRFC5280Conformant: Bool {
        guard self.version != .v3 else { return false }
        return self.version == self.minimumRequiredVersion
    }
}

extension RFC_5280.TBSCertList: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        self = try ISO_8825.DER.sequence(node, identifier: identifier) { (nodes: inout ISO_8825.Node.Collection.Iterator) throws(ISO_8824.Error) -> Self in
            let rawVersion: Int? = try ISO_8825.DER.optionalImplicitlyTagged(&nodes, tag: .integer)
            let signature = try RFC_5280.AlgorithmIdentifier(derEncoded: &nodes)
            let issuer = try RFC_5280.Name(derEncoded: &nodes)
            let thisUpdate = try RFC_5280.Time(derEncoded: &nodes)

            var nextUpdate: RFC_5280.Time?
            var revokedCertificates: [RFC_5280.TBSCertList.RevokedCertificate] = []
            var crlExtensions: [RFC_5280.Extension] = []

            while let child = nodes.next() {
                switch child.identifier {
                case ISO_8824.UTCTime.defaultIdentifier, ISO_8824.GeneralizedTime.defaultIdentifier:
                    nextUpdate = try RFC_5280.Time(derEncoded: child)
                case ISO_8824.Identifier.sequence:
                    revokedCertificates = try ISO_8825.DER.sequence(
                        of: RFC_5280.TBSCertList.RevokedCertificate.self,
                        identifier: .sequence,
                        rootNode: child
                    )
                case ISO_8824.Identifier(tagWithNumber: 0, tagClass: .contextSpecific):
                    guard case .constructed(let children) = child.content else {
                        throw ISO_8824.Error.invalidASN1Object(reason: "crlExtensions explicit tag must be constructed")
                    }
                    var wrapped = children.makeIterator()
                    guard let extensionsNode = wrapped.next(), wrapped.next() == nil else {
                        throw ISO_8824.Error.invalidASN1Object(reason: "crlExtensions explicit tag must wrap exactly one Extensions")
                    }
                    crlExtensions = try ISO_8825.DER.sequence(
                        of: RFC_5280.Extension.self,
                        identifier: .sequence,
                        rootNode: extensionsNode
                    )
                    guard !crlExtensions.isEmpty else {
                        throw ISO_8824.Error.invalidASN1Object(
                            reason: "Extensions is SEQUENCE SIZE (1..MAX); an empty list must be encoded as an absent field"
                        )
                    }
                default:
                    throw ISO_8824.Error.unexpectedFieldType(child.identifier)
                }
            }

            return Self(
                version: rawVersion.map { RFC_5280.Certificate.Version(rawValue: $0) },
                signature: signature,
                issuer: issuer,
                thisUpdate: thisUpdate,
                nextUpdate: nextUpdate,
                revokedCertificates: revokedCertificates,
                crlExtensions: crlExtensions
            )
        }
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            if let version = self.version {
                try coder.serialize(version.rawValue)
            }
            try coder.serialize(self.signature)
            try coder.serialize(self.issuer)
            try coder.serialize(self.thisUpdate)
            if let nextUpdate = self.nextUpdate {
                try coder.serialize(nextUpdate)
            }
            if !self.revokedCertificates.isEmpty {
                try coder.appendConstructedNode(identifier: .sequence) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
                    for revoked in self.revokedCertificates {
                        try coder.serialize(revoked)
                    }
                }
            }
            if !self.crlExtensions.isEmpty {
                try coder.serialize(explicitlyTaggedWithTagNumber: 0, tagClass: .contextSpecific) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
                    try coder.appendConstructedNode(identifier: .sequence) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
                        for crlExtension in self.crlExtensions {
                            try coder.serialize(crlExtension)
                        }
                    }
                }
            }
        }
    }
}
