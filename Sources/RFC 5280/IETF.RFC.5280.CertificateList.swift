public import ISO_8824
public import ISO_8825

extension IETF.RFC.`5280` {
    /// `CertificateList ::= SEQUENCE { tbsCertList TBSCertList,
    /// signatureAlgorithm AlgorithmIdentifier, signatureValue BIT STRING }`
    /// (RFC 5280 §5.1).
    ///
    /// The signed CRL object. Unlike the certificate profile — where the
    /// outer `Certificate` SEQUENCE is the certificate runtime's type and
    /// this module owns only ``RFC_5280/TBSCertificate`` — RFC 5280 is the
    /// sole owner of the CRL structure, so the outer object is modelled
    /// here.
    ///
    /// Verifying ``signatureValue`` over the encoded ``tbsCertList``
    /// requires a cryptographic witness and is therefore runtime law, not
    /// wire law; this type carries the wire structure and the §5.1.1.2
    /// consistency rule that ``signatureAlgorithm`` MUST equal
    /// ``RFC_5280/TBSCertList/signature`` (``hasConsistentSignatureAlgorithm``).
    public struct CertificateList: Hashable, Sendable {
        /// The to-be-signed certificate list.
        public var tbsCertList: IETF.RFC.`5280`.TBSCertList

        /// The algorithm the CRL issuer used to sign ``tbsCertList``.
        public var signatureAlgorithm: IETF.RFC.`5280`.AlgorithmIdentifier

        /// The signature over the DER encoding of ``tbsCertList``.
        public var signatureValue: ISO.`8824`.BitString

        public init(
            tbsCertList: IETF.RFC.`5280`.TBSCertList,
            signatureAlgorithm: IETF.RFC.`5280`.AlgorithmIdentifier,
            signatureValue: ISO.`8824`.BitString
        ) {
            self.tbsCertList = tbsCertList
            self.signatureAlgorithm = signatureAlgorithm
            self.signatureValue = signatureValue
        }
    }
}

extension IETF.RFC.`5280`.CertificateList {
    /// Whether ``signatureAlgorithm`` equals ``RFC_5280/TBSCertList/signature``,
    /// as §5.1.1.2 requires.
    ///
    /// A mismatch is preserved for wire fidelity and reported here: it is a
    /// signature-substitution signal a verifier must act on.
    public var hasConsistentSignatureAlgorithm: Bool {
        self.signatureAlgorithm == self.tbsCertList.signature
    }
}

extension IETF.RFC.`5280`.CertificateList: ISO.`8825`.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO.`8824`.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO.`8825`.Node, withIdentifier identifier: ISO.`8824`.Identifier) throws(ISO.`8824`.Error) {
        self = try ISO.`8825`.DER.sequence(node, identifier: identifier) { (nodes: inout ISO.`8825`.Node.Collection.Iterator) throws(ISO.`8824`.Error) -> Self in
            let tbsCertList = try IETF.RFC.`5280`.TBSCertList(derEncoded: &nodes)
            let signatureAlgorithm = try IETF.RFC.`5280`.AlgorithmIdentifier(derEncoded: &nodes)
            let signatureValue = try ISO.`8824`.BitString(derEncoded: &nodes)
            return Self(
                tbsCertList: tbsCertList,
                signatureAlgorithm: signatureAlgorithm,
                signatureValue: signatureValue
            )
        }
    }

    public func serialize(into coder: inout ISO.`8825`.DER.Serializer, withIdentifier identifier: ISO.`8824`.Identifier) throws(ISO.`8824`.Error) {
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO.`8825`.DER.Serializer) throws(ISO.`8824`.Error) in
            try coder.serialize(self.tbsCertList)
            try coder.serialize(self.signatureAlgorithm)
            try coder.serialize(self.signatureValue)
        }
    }
}
