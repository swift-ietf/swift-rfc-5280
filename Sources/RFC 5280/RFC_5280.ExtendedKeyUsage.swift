public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId` with
    /// `KeyPurposeId ::= OBJECT IDENTIFIER` (RFC 5280 §4.2.1.12).
    ///
    /// Criticality law: this extension MAY be either critical or
    /// non-critical, at the issuing CA's discretion. If a certificate
    /// contains both `keyUsage` and this extension, both MUST be processed
    /// independently and the certificate used only for purposes consistent
    /// with both. The special `anyExtendedKeyUsage` purpose
    /// (``RFC_5280/ExtendedKeyUsage/ID/anyExtendedKeyUsage``) indicates no
    /// purpose restriction; CAs SHOULD NOT mark this extension critical when
    /// it is present.
    public struct ExtendedKeyUsage: Hashable, Sendable {
        /// The key purposes, in wire order. Must contain at least one
        /// purpose; the SIZE (1..MAX) bound is enforced at the wire boundary.
        public var keyPurposeIDs: [ISO_8824.ObjectIdentifier]

        public init(_ keyPurposeIDs: [ISO_8824.ObjectIdentifier]) {
            self.keyPurposeIDs = keyPurposeIDs
        }
    }
}

extension RFC_5280.ExtendedKeyUsage: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        let keyPurposeIDs = try ISO_8825.DER.sequence(
            of: ISO_8824.ObjectIdentifier.self,
            identifier: identifier,
            rootNode: node
        )
        guard !keyPurposeIDs.isEmpty else {
            throw ISO_8824.Error.invalidASN1Object(reason: "ExtKeyUsageSyntax is SEQUENCE SIZE (1..MAX) OF KeyPurposeId; got an empty sequence")
        }
        self.keyPurposeIDs = keyPurposeIDs
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        guard !self.keyPurposeIDs.isEmpty else {
            throw ISO_8824.Error.invalidASN1Object(reason: "ExtKeyUsageSyntax is SEQUENCE SIZE (1..MAX) OF KeyPurposeId; got an empty sequence")
        }
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            for keyPurposeID in self.keyPurposeIDs {
                try coder.serialize(keyPurposeID)
            }
        }
    }
}

extension RFC_5280.ExtendedKeyUsage {
    /// `id-ce-extKeyUsage` (§4.2.1.12).
    public static var extensionID: ISO_8824.ObjectIdentifier {
        RFC_5280.Extension.ID.extendedKeyUsage
    }

    /// Decodes the typed value from a generic ``RFC_5280/Extension``.
    public init(_ certificateExtension: RFC_5280.Extension) throws(ISO_8824.Error) {
        guard certificateExtension.extnID == Self.extensionID else {
            throw ISO_8824.Error.invalidASN1Object(reason: "Expected id-ce-extKeyUsage, got \(certificateExtension.extnID)")
        }
        self = try Self(derEncoded: certificateExtension.extnValue.bytes)
    }

    /// Wraps this value as a generic ``RFC_5280/Extension``.
    ///
    /// §4.2.1.12 leaves criticality to the issuing CA; the default is
    /// non-critical.
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
