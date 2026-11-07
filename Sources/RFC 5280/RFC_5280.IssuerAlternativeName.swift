public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `IssuerAltName ::= GeneralNames` with `GeneralNames ::= SEQUENCE
    /// SIZE (1..MAX) OF GeneralName` (RFC 5280 §4.2.1.7).
    ///
    /// Binds additional identities to the certificate's issuer. Where
    /// present, conforming CAs SHOULD mark this extension as non-critical.
    /// Issuer alternative names are not part of the issuer/subject chaining
    /// law — a path is chained on the `issuer` and `subject` distinguished
    /// names, so this extension never substitutes for a non-empty issuer
    /// name (§4.1.2.4).
    public struct IssuerAlternativeName: Hashable, Sendable {
        /// The alternative names, in wire order. Must contain at least one;
        /// the SIZE (1..MAX) bound is enforced at the wire boundary.
        public var names: [RFC_5280.GeneralName]

        public init(_ names: [RFC_5280.GeneralName]) {
            self.names = names
        }
    }
}

extension RFC_5280.IssuerAlternativeName: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        let names = try ISO_8825.DER.sequence(
            of: RFC_5280.GeneralName.self,
            identifier: identifier,
            rootNode: node
        )
        guard !names.isEmpty else {
            throw ISO_8824.Error.invalidASN1Object(
                reason: "GeneralNames is SEQUENCE SIZE (1..MAX) OF GeneralName; got an empty sequence"
            )
        }
        self.names = names
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        guard !self.names.isEmpty else {
            throw ISO_8824.Error.invalidASN1Object(
                reason: "GeneralNames is SEQUENCE SIZE (1..MAX) OF GeneralName; got an empty sequence"
            )
        }
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            for name in self.names {
                try coder.serialize(name)
            }
        }
    }
}

extension RFC_5280.IssuerAlternativeName {
    /// `id-ce-issuerAltName` (§4.2.1.7).
    public static var extensionID: ISO_8824.ObjectIdentifier {
        RFC_5280.Extension.ID.issuerAlternativeName
    }

    /// Decodes the typed value from a generic ``RFC_5280/Extension``.
    public init(_ certificateExtension: RFC_5280.Extension) throws(ISO_8824.Error) {
        guard certificateExtension.extnID == Self.extensionID else {
            throw ISO_8824.Error.invalidASN1Object(reason: "Expected id-ce-issuerAltName, got \(certificateExtension.extnID)")
        }
        self = try Self(derEncoded: certificateExtension.extnValue.bytes)
    }

    /// Wraps this value as a generic ``RFC_5280/Extension``.
    ///
    /// §4.2.1.7 criticality law: where present, conforming CAs SHOULD mark
    /// this extension non-critical, hence the default.
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
