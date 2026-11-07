public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `CRLNumber ::= INTEGER (0..MAX)` (RFC 5280 §5.2.3).
    ///
    /// A monotonically increasing sequence number for a given CRL scope and
    /// issuer, letting a relying party tell whether one CRL supersedes
    /// another.
    ///
    /// Criticality law: conforming CAs MUST include this extension in all
    /// CRLs and MUST mark it non-critical. CRL numbers may exceed the range
    /// of common fixed-width integers — conforming CRL issuers MUST use a
    /// value no longer than 20 octets — so the value is carried as the
    /// INTEGER's content octets rather than a machine integer.
    public struct CRLNumber: Hashable, Sendable {
        /// The big-endian two's-complement content octets of the INTEGER,
        /// exactly as they appear on the wire (minimal DER form).
        public var bytes: ArraySlice<UInt8>

        public init(bytes: ArraySlice<UInt8>) {
            self.bytes = bytes
        }
    }
}

extension RFC_5280.CRLNumber {
    /// Creates a CRL number from an unsigned integer value.
    public init(_ value: some FixedWidthInteger & UnsignedInteger) {
        var content: [UInt8] = []
        var remaining = value
        while remaining > 0 {
            content.append(UInt8(truncatingIfNeeded: remaining))
            remaining >>= 8
        }
        if content.isEmpty {
            content = [0]
        }
        content.reverse()
        if let first = content.first, first & 0x80 == 0x80 {
            content.insert(0, at: 0)
        }
        self.bytes = content[...]
    }

    /// Whether this value satisfies the §5.2.3 issuance law: a non-negative
    /// integer of at most 20 content octets.
    public var isRFC5280Conformant: Bool {
        guard let first = self.bytes.first else { return false }
        guard first & 0x80 == 0 else { return false }
        return self.bytes.count <= 20
    }
}

extension RFC_5280.CRLNumber: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        .integer
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        self.bytes = try ArraySlice<UInt8>(derEncoded: node, withIdentifier: identifier)
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        try self.bytes.serialize(into: &coder, withIdentifier: identifier)
    }
}

extension RFC_5280.CRLNumber {
    /// `id-ce-cRLNumber` (§5.2.3).
    public static var extensionID: ISO_8824.ObjectIdentifier {
        RFC_5280.Extension.ID.cRLNumber
    }

    /// Decodes the typed value from a generic ``RFC_5280/Extension``.
    public init(_ certificateExtension: RFC_5280.Extension) throws(ISO_8824.Error) {
        guard certificateExtension.extnID == Self.extensionID else {
            throw ISO_8824.Error.invalidASN1Object(reason: "Expected id-ce-cRLNumber, got \(certificateExtension.extnID)")
        }
        self = try Self(derEncoded: certificateExtension.extnValue.bytes)
    }

    /// Wraps this value as a generic ``RFC_5280/Extension``.
    ///
    /// §5.2.3 criticality law: conforming CAs MUST mark this extension
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
