// RFC_5280.ReasonFlags.swift
// RFC 5280 §4.2.1.13 — CRL Distribution Points: ReasonFlags
// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13

public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `ReasonFlags ::= BIT STRING { unused(0), keyCompromise(1),
    /// cACompromise(2), affiliationChanged(3), superseded(4),
    /// cessationOfOperation(5), certificateHold(6), privilegeWithdrawn(7),
    /// aACompromise(8) }` (RFC 5280 §4.2.1.13).
    ///
    /// Names the revocation reasons a distribution point covers. When the
    /// `reasons` field of a ``RFC_5280/DistributionPoint`` is absent, the
    /// distribution point covers all reasons.
    ///
    /// DER named-bit law: trailing zero bits MUST NOT be encoded, so the
    /// BIT STRING carries only up to the highest set bit — an all-zero
    /// value encodes as an empty BIT STRING.
    public struct ReasonFlags: Hashable, Sendable {
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

extension RFC_5280.ReasonFlags {
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

    /// Named bit 0 — reserved, and not a revocation reason.
    public var unused: Bool {
        get { self[bit: 0] }
        set { self[bit: 0] = newValue }
    }

    /// Named bit 1.
    public var keyCompromise: Bool {
        get { self[bit: 1] }
        set { self[bit: 1] = newValue }
    }

    /// Named bit 2.
    public var cACompromise: Bool {
        get { self[bit: 2] }
        set { self[bit: 2] = newValue }
    }

    /// Named bit 3.
    public var affiliationChanged: Bool {
        get { self[bit: 3] }
        set { self[bit: 3] = newValue }
    }

    /// Named bit 4.
    public var superseded: Bool {
        get { self[bit: 4] }
        set { self[bit: 4] = newValue }
    }

    /// Named bit 5.
    public var cessationOfOperation: Bool {
        get { self[bit: 5] }
        set { self[bit: 5] = newValue }
    }

    /// Named bit 6.
    public var certificateHold: Bool {
        get { self[bit: 6] }
        set { self[bit: 6] = newValue }
    }

    /// Named bit 7.
    public var privilegeWithdrawn: Bool {
        get { self[bit: 7] }
        set { self[bit: 7] = newValue }
    }

    /// Named bit 8.
    public var aACompromise: Bool {
        get { self[bit: 8] }
        set { self[bit: 8] = newValue }
    }
}

extension RFC_5280.ReasonFlags: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        ISO_8824.BitString.defaultIdentifier
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        let bits = try ISO_8824.BitString(derEncoded: node, withIdentifier: identifier)
        guard bits.bytes.count <= 2 else {
            throw ISO_8824.Error.invalidASN1Object(reason: "ReasonFlags defines named bits 0–8; got \(bits.bytes.count) content octets")
        }
        var rawValue: UInt16 = 0
        for (offset, byte) in bits.bytes.enumerated() {
            rawValue |= UInt16(byte) << (8 * (1 - offset))
        }
        // Named bits stop at aACompromise(8); bits 9–15 are undefined.
        guard rawValue & 0x007F == 0 else {
            throw ISO_8824.Error.invalidASN1Object(reason: "ReasonFlags carries set bits beyond aACompromise(8)")
        }
        self.rawValue = rawValue
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        // DER named-bit law: encode only through the highest set bit.
        let bits: ISO_8824.BitString
        if self.rawValue == 0 {
            bits = try ISO_8824.BitString(bytes: [], paddingBits: 0)
        } else {
            let highestSetBit = 15 - self.rawValue.trailingZeroBitCount
            if highestSetBit <= 7 {
                bits = try ISO_8824.BitString(
                    bytes: [UInt8(self.rawValue >> 8)],
                    paddingBits: 7 - highestSetBit
                )
            } else {
                bits = try ISO_8824.BitString(
                    bytes: [UInt8(self.rawValue >> 8), UInt8(truncatingIfNeeded: self.rawValue)],
                    paddingBits: 15 - highestSetBit
                )
            }
        }
        try bits.serialize(into: &coder, withIdentifier: identifier)
    }
}
