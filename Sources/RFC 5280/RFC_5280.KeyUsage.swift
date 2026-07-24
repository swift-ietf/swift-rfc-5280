// RFC_5280.KeyUsage.swift
// RFC 5280 §4.2.1.3 — Key Usage
// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.3

public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `KeyUsage ::= BIT STRING { digitalSignature(0), nonRepudiation(1),
    /// keyEncipherment(2), dataEncipherment(3), keyAgreement(4),
    /// keyCertSign(5), cRLSign(6), encipherOnly(7), decipherOnly(8) }`
    /// (RFC 5280 §4.2.1.3). Bit 1 is also named `contentCommitment` in
    /// recent editions of X.509.
    ///
    /// Criticality law: when this extension appears, conforming CAs SHOULD
    /// mark it critical; when it appears, at least one bit MUST be set.
    /// `encipherOnly`/`decipherOnly` are meaningful only alongside
    /// `keyAgreement`. DER named-bit law: trailing zero bits MUST NOT be
    /// encoded, so the BIT STRING carries only up to the highest set bit —
    /// an all-zero value encodes as an empty BIT STRING.
    public struct KeyUsage: Hashable, Sendable {
        /// The named bits in wire order: named bit `i` is mask `0x8000 >> i`
        /// (bit 0 = first transmitted bit, per X.680 named-bit numbering).
        public var rawValue: UInt16

        public init(rawValue: UInt16) {
            self.rawValue = rawValue
        }

        public init() {
            self.rawValue = 0
        }
    }
}

extension RFC_5280.KeyUsage {
    private subscript(bit bit: Int) -> Bool {
        get { self.rawValue & (0x8000 >> bit) != 0 }
        set {
            if newValue {
                self.rawValue |= (0x8000 >> bit)
            } else {
                self.rawValue &= ~(0x8000 >> bit)
            }
        }
    }

    /// Named bit 0.
    public var digitalSignature: Bool {
        get { self[bit: 0] }
        set { self[bit: 0] = newValue }
    }

    /// Named bit 1 (`contentCommitment` in current X.509).
    public var nonRepudiation: Bool {
        get { self[bit: 1] }
        set { self[bit: 1] = newValue }
    }

    /// Named bit 2.
    public var keyEncipherment: Bool {
        get { self[bit: 2] }
        set { self[bit: 2] = newValue }
    }

    /// Named bit 3.
    public var dataEncipherment: Bool {
        get { self[bit: 3] }
        set { self[bit: 3] = newValue }
    }

    /// Named bit 4.
    public var keyAgreement: Bool {
        get { self[bit: 4] }
        set { self[bit: 4] = newValue }
    }

    /// Named bit 5.
    public var keyCertSign: Bool {
        get { self[bit: 5] }
        set { self[bit: 5] = newValue }
    }

    /// Named bit 6.
    public var cRLSign: Bool {
        get { self[bit: 6] }
        set { self[bit: 6] = newValue }
    }

    /// Named bit 7.
    public var encipherOnly: Bool {
        get { self[bit: 7] }
        set { self[bit: 7] = newValue }
    }

    /// Named bit 8.
    public var decipherOnly: Bool {
        get { self[bit: 8] }
        set { self[bit: 8] = newValue }
    }
}

extension RFC_5280.KeyUsage: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        ISO_8824.BitString.defaultIdentifier
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        let bits = try ISO_8824.BitString(derEncoded: node, withIdentifier: identifier)
        guard bits.bytes.count <= 2 else {
            throw ISO_8824.Error.invalidASN1Object(reason: "KeyUsage defines named bits 0–8; got \(bits.bytes.count) content octets")
        }
        var rawValue: UInt16 = 0
        for (offset, byte) in bits.bytes.enumerated() {
            rawValue |= UInt16(byte) << (8 * (1 - offset))
        }
        // Named bits stop at decipherOnly(8); bits 9–15 are undefined.
        guard rawValue & 0x007F == 0 else {
            throw ISO_8824.Error.invalidASN1Object(reason: "KeyUsage carries set bits beyond decipherOnly(8)")
        }
        self.rawValue = rawValue
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        // DER named-bit law: encode only through the highest set bit.
        let bits: ISO_8824.BitString
        if self.rawValue == 0 {
            bits = ISO_8824.BitString(bytes: [], paddingBits: 0)
        } else {
            let highestSetBit = 15 - self.rawValue.trailingZeroBitCount
            if highestSetBit <= 7 {
                bits = ISO_8824.BitString(
                    bytes: [UInt8(self.rawValue >> 8)],
                    paddingBits: 7 - highestSetBit
                )
            } else {
                bits = ISO_8824.BitString(
                    bytes: [UInt8(self.rawValue >> 8), UInt8(truncatingIfNeeded: self.rawValue)],
                    paddingBits: 15 - highestSetBit
                )
            }
        }
        try bits.serialize(into: &coder, withIdentifier: identifier)
    }
}

extension RFC_5280.KeyUsage {
    /// `id-ce-keyUsage` (§4.2.1.3).
    public static var extensionID: ISO_8824.ObjectIdentifier {
        RFC_5280.Extension.ID.keyUsage
    }

    /// Decodes the typed value from a generic ``RFC_5280/Extension``.
    public init(_ certificateExtension: RFC_5280.Extension) throws(ISO_8824.Error) {
        guard certificateExtension.extnID == Self.extensionID else {
            throw ISO_8824.Error.invalidASN1Object(reason: "Expected id-ce-keyUsage, got \(certificateExtension.extnID)")
        }
        self = try Self(derEncoded: certificateExtension.extnValue.bytes)
    }

    /// Wraps this value as a generic ``RFC_5280/Extension``.
    ///
    /// §4.2.1.3 criticality law: when used, this extension SHOULD be
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
