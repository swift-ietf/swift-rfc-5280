// RFC_5280.TBSCertificate.swift
// RFC 5280 §4.1.2 — TBSCertificate
// https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2

public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `TBSCertificate ::= SEQUENCE { version [0] EXPLICIT Version DEFAULT v1,
    /// serialNumber CertificateSerialNumber, signature AlgorithmIdentifier,
    /// issuer Name, validity Validity, subject Name, subjectPublicKeyInfo
    /// SubjectPublicKeyInfo, issuerUniqueID [1] IMPLICIT UniqueIdentifier
    /// OPTIONAL, subjectUniqueID [2] IMPLICIT UniqueIdentifier OPTIONAL,
    /// extensions [3] EXPLICIT Extensions OPTIONAL }` (RFC 5280 §4.1.2).
    ///
    /// Version law (§4.1.2.1): `extensions` non-empty requires `v3`; unique
    /// identifiers without extensions require `v2` or `v3`; a plain
    /// certificate MUST be `v1` — see ``minimumRequiredVersion``. The unique
    /// identifier fields appear only in `v2`/`v3` and CAs conforming to this
    /// profile MUST NOT generate them (§4.1.2.8). `Extensions ::= SEQUENCE
    /// SIZE (1..MAX) OF Extension`, so an empty ``extensions`` array encodes
    /// as an absent `[3]` field.
    ///
    /// The `signature` field MUST contain the same algorithm identifier as
    /// the outer certificate's `signatureAlgorithm` (§4.1.2.3) — a
    /// cross-structure law the certificate runtime enforces.
    public struct TBSCertificate: Hashable, Sendable {
        public var version: RFC_5280.Certificate.Version
        public var serialNumber: RFC_5280.Certificate.SerialNumber
        public var signature: RFC_5280.AlgorithmIdentifier
        public var issuer: RFC_5280.Name
        public var validity: RFC_5280.Validity
        public var subject: RFC_5280.Name
        public var subjectPublicKeyInfo: RFC_5280.SubjectPublicKeyInfo
        public var issuerUniqueID: ISO_8824.BitString?
        public var subjectUniqueID: ISO_8824.BitString?
        public var extensions: [RFC_5280.Extension]

        public init(
            version: RFC_5280.Certificate.Version,
            serialNumber: RFC_5280.Certificate.SerialNumber,
            signature: RFC_5280.AlgorithmIdentifier,
            issuer: RFC_5280.Name,
            validity: RFC_5280.Validity,
            subject: RFC_5280.Name,
            subjectPublicKeyInfo: RFC_5280.SubjectPublicKeyInfo,
            issuerUniqueID: ISO_8824.BitString? = nil,
            subjectUniqueID: ISO_8824.BitString? = nil,
            extensions: [RFC_5280.Extension] = []
        ) {
            self.version = version
            self.serialNumber = serialNumber
            self.signature = signature
            self.issuer = issuer
            self.validity = validity
            self.subject = subject
            self.subjectPublicKeyInfo = subjectPublicKeyInfo
            self.issuerUniqueID = issuerUniqueID
            self.subjectUniqueID = subjectUniqueID
            self.extensions = extensions
        }

        /// The lowest version §4.1.2.1 permits for this certificate's
        /// populated fields: `v3` when extensions are present, `v2` when
        /// unique identifiers are present without extensions, `v1` otherwise.
        public var minimumRequiredVersion: RFC_5280.Certificate.Version {
            if !self.extensions.isEmpty {
                return .v3
            }
            if self.issuerUniqueID != nil || self.subjectUniqueID != nil {
                return .v2
            }
            return .v1
        }
    }
}

extension RFC_5280.TBSCertificate: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        self = try ISO_8825.DER.sequence(node, identifier: identifier) { (nodes: inout ISO_8825.Node.Collection.Iterator) throws(ISO_8824.Error) -> Self in
            let rawVersion = try ISO_8825.DER.decodeDefaultExplicitlyTagged(
                &nodes,
                tagNumber: 0,
                tagClass: .contextSpecific,
                defaultValue: 0
            )
            let serialNumber = try RFC_5280.Certificate.SerialNumber(derEncoded: &nodes)
            let signature = try RFC_5280.AlgorithmIdentifier(derEncoded: &nodes)
            let issuer = try RFC_5280.Name(derEncoded: &nodes)
            let validity = try RFC_5280.Validity(derEncoded: &nodes)
            let subject = try RFC_5280.Name(derEncoded: &nodes)
            let subjectPublicKeyInfo = try RFC_5280.SubjectPublicKeyInfo(derEncoded: &nodes)
            let issuerUniqueID: ISO_8824.BitString? = try ISO_8825.DER.optionalImplicitlyTagged(
                &nodes,
                tag: ISO_8824.Identifier(tagWithNumber: 1, tagClass: .contextSpecific)
            )
            let subjectUniqueID: ISO_8824.BitString? = try ISO_8825.DER.optionalImplicitlyTagged(
                &nodes,
                tag: ISO_8824.Identifier(tagWithNumber: 2, tagClass: .contextSpecific)
            )
            let extensions = try ISO_8825.DER.optionalExplicitlyTagged(&nodes, tagNumber: 3, tagClass: .contextSpecific) { node throws(ISO_8824.Error) in
                let extensions = try ISO_8825.DER.sequence(of: RFC_5280.Extension.self, identifier: .sequence, rootNode: node)
                guard !extensions.isEmpty else {
                    throw ISO_8824.Error.invalidASN1Object(reason: "Extensions is SEQUENCE SIZE (1..MAX); an empty list must be encoded as an absent field")
                }
                return extensions
            }
            return Self(
                version: RFC_5280.Certificate.Version(rawValue: rawVersion),
                serialNumber: serialNumber,
                signature: signature,
                issuer: issuer,
                validity: validity,
                subject: subject,
                subjectPublicKeyInfo: subjectPublicKeyInfo,
                issuerUniqueID: issuerUniqueID,
                subjectUniqueID: subjectUniqueID,
                extensions: extensions ?? []
            )
        }
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            // DEFAULT v1: DER MUST omit the [0] field for version 1.
            if self.version != .v1 {
                try coder.serialize(self.version.rawValue, explicitlyTaggedWithTagNumber: 0, tagClass: .contextSpecific)
            }
            try coder.serialize(self.serialNumber)
            try coder.serialize(self.signature)
            try coder.serialize(self.issuer)
            try coder.serialize(self.validity)
            try coder.serialize(self.subject)
            try coder.serialize(self.subjectPublicKeyInfo)
            try coder.serializeOptionalImplicitlyTagged(
                self.issuerUniqueID,
                withIdentifier: ISO_8824.Identifier(tagWithNumber: 1, tagClass: .contextSpecific)
            )
            try coder.serializeOptionalImplicitlyTagged(
                self.subjectUniqueID,
                withIdentifier: ISO_8824.Identifier(tagWithNumber: 2, tagClass: .contextSpecific)
            )
            if !self.extensions.isEmpty {
                try coder.serialize(explicitlyTaggedWithTagNumber: 3, tagClass: .contextSpecific) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
                    try coder.appendConstructedNode(identifier: .sequence) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
                        for `extension` in self.extensions {
                            try coder.serialize(`extension`)
                        }
                    }
                }
            }
        }
    }
}
