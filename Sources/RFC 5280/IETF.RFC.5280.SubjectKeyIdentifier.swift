public import ISO_8824
public import ISO_8825

extension IETF.RFC.`5280` {
    /// `SubjectKeyIdentifier ::= KeyIdentifier` with `KeyIdentifier ::=
    /// OCTET STRING` (RFC 5280 §4.2.1.2).
    ///
    /// Criticality law: conforming CAs MUST mark this extension
    /// non-critical, and MUST include it in all CA certificates. The two
    /// common derivation methods (SHA-1 of the subject public key BIT
    /// STRING, or the truncated `0100`-prefixed 60-bit form) require a hash
    /// witness and therefore live with the cryptographic runtime, not here.
    public struct SubjectKeyIdentifier: Hashable, Sendable {
        /// The key identifier octets.
        public var keyIdentifier: ISO.`8824`.OctetString

        public init(keyIdentifier: ISO.`8824`.OctetString) {
            self.keyIdentifier = keyIdentifier
        }
    }
}

extension IETF.RFC.`5280`.SubjectKeyIdentifier: ISO.`8825`.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO.`8824`.Identifier {
        ISO.`8824`.OctetString.defaultIdentifier
    }

    public init(derEncoded node: ISO.`8825`.Node, withIdentifier identifier: ISO.`8824`.Identifier) throws(ISO.`8824`.Error) {
        self.keyIdentifier = try ISO.`8824`.OctetString(derEncoded: node, withIdentifier: identifier)
    }

    public func serialize(into coder: inout ISO.`8825`.DER.Serializer, withIdentifier identifier: ISO.`8824`.Identifier) throws(ISO.`8824`.Error) {
        try self.keyIdentifier.serialize(into: &coder, withIdentifier: identifier)
    }
}

extension IETF.RFC.`5280`.SubjectKeyIdentifier {
    /// `id-ce-subjectKeyIdentifier` (§4.2.1.2).
    public static var extensionID: ISO.`8824`.ObjectIdentifier {
        IETF.RFC.`5280`.Extension.ID.subjectKeyIdentifier
    }

    /// Decodes the typed value from a generic ``RFC_5280/Extension``.
    public init(_ certificateExtension: IETF.RFC.`5280`.Extension) throws(ISO.`8824`.Error) {
        guard certificateExtension.extnID == Self.extensionID else {
            throw ISO.`8824`.Error.invalidASN1Object(reason: "Expected id-ce-subjectKeyIdentifier, got \(certificateExtension.extnID)")
        }
        self = try Self(derEncoded: certificateExtension.extnValue.bytes)
    }

    /// Wraps this value as a generic ``RFC_5280/Extension``.
    ///
    /// §4.2.1.2 criticality law: conforming CAs MUST mark this extension
    /// non-critical, hence the default.
    public func makeExtension(critical: Bool = false) throws(ISO.`8824`.Error) -> IETF.RFC.`5280`.Extension {
        var serializer = ISO.`8825`.DER.Serializer()
        try serializer.serialize(self)
        return IETF.RFC.`5280`.Extension(
            extnID: Self.extensionID,
            critical: critical,
            extnValue: ISO.`8824`.OctetString(contentBytes: serializer.serializedBytes[...])
        )
    }
}
