public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `InvalidityDate ::= GeneralizedTime` (RFC 5280 §5.3.2).
    ///
    /// The date on which the private key is known or suspected to have been
    /// compromised, which may precede the CRL entry's `revocationDate`. It
    /// is a non-authoritative hint: a relying party may have other evidence
    /// of an earlier compromise.
    ///
    /// Criticality law: conforming CAs MUST mark this extension
    /// non-critical. Unlike §4.1.2.5 certificate validity, this field is
    /// always `GeneralizedTime` — there is no UTCTime cutover here.
    public struct InvalidityDate: Hashable, Sendable {
        /// The invalidity date.
        public var date: ISO_8824.GeneralizedTime

        public init(date: ISO_8824.GeneralizedTime) {
            self.date = date
        }
    }
}

extension RFC_5280.InvalidityDate: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        ISO_8824.GeneralizedTime.defaultIdentifier
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        self.date = try ISO_8824.GeneralizedTime(derEncoded: node, withIdentifier: identifier)
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        try self.date.serialize(into: &coder, withIdentifier: identifier)
    }
}

extension RFC_5280.InvalidityDate {
    /// `id-ce-invalidityDate` (§5.3.2).
    public static var extensionID: ISO_8824.ObjectIdentifier {
        RFC_5280.Extension.ID.invalidityDate
    }

    /// Decodes the typed value from a generic ``RFC_5280/Extension``.
    public init(_ certificateExtension: RFC_5280.Extension) throws(ISO_8824.Error) {
        guard certificateExtension.extnID == Self.extensionID else {
            throw ISO_8824.Error.invalidASN1Object(reason: "Expected id-ce-invalidityDate, got \(certificateExtension.extnID)")
        }
        self = try Self(derEncoded: certificateExtension.extnValue.bytes)
    }

    /// Wraps this value as a generic ``RFC_5280/Extension``.
    ///
    /// §5.3.2 criticality law: conforming CAs MUST mark this extension
    /// non-critical, hence the default.
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
