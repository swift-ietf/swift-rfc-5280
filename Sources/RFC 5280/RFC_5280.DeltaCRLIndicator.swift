public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `BaseCRLNumber ::= CRLNumber` (RFC 5280 §5.2.4).
    ///
    /// Identifies a CRL as a delta CRL and names the CRL number of the base
    /// CRL it is computed against. It shares ``RFC_5280/CRLNumber``'s syntax
    /// but is a distinct extension with its own identifier and criticality
    /// law, so it is modelled as its own type rather than an alias.
    ///
    /// Criticality law: conforming CAs MUST mark this extension as critical
    /// — a relying party that does not understand delta CRLs must not treat
    /// one as a complete CRL.
    public struct DeltaCRLIndicator: Hashable, Sendable {
        /// The CRL number of the base CRL this delta is computed against.
        public var baseCRLNumber: RFC_5280.CRLNumber

        public init(baseCRLNumber: RFC_5280.CRLNumber) {
            self.baseCRLNumber = baseCRLNumber
        }
    }
}

extension RFC_5280.DeltaCRLIndicator: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        .integer
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        self.baseCRLNumber = try RFC_5280.CRLNumber(derEncoded: node, withIdentifier: identifier)
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        try self.baseCRLNumber.serialize(into: &coder, withIdentifier: identifier)
    }
}

extension RFC_5280.DeltaCRLIndicator {
    /// `id-ce-deltaCRLIndicator` (§5.2.4).
    public static var extensionID: ISO_8824.ObjectIdentifier {
        RFC_5280.Extension.ID.deltaCRLIndicator
    }

    /// Decodes the typed value from a generic ``RFC_5280/Extension``.
    public init(_ certificateExtension: RFC_5280.Extension) throws(ISO_8824.Error) {
        guard certificateExtension.extnID == Self.extensionID else {
            throw ISO_8824.Error.invalidASN1Object(reason: "Expected id-ce-deltaCRLIndicator, got \(certificateExtension.extnID)")
        }
        self = try Self(derEncoded: certificateExtension.extnValue.bytes)
    }

    /// Wraps this value as a generic ``RFC_5280/Extension``.
    ///
    /// §5.2.4 criticality law: conforming CAs MUST mark this extension
    /// critical, hence the default.
    public func makeExtension(critical: Bool = true) throws(ISO_8824.Error) -> RFC_5280.Extension {
        var serializer = ISO_8825.DER.Serializer()
        try serializer.serialize(self)
        return RFC_5280.Extension(
            extnID: Self.extensionID,
            critical: critical,
            extnValue: ISO_8824.OctetString(contentBytes: serializer.serializedBytes[...])
        )
    }
}
