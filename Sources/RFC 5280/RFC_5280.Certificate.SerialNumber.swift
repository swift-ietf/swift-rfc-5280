public import ISO_8824
public import ISO_8825

extension RFC_5280.Certificate {
    /// `CertificateSerialNumber ::= INTEGER` (RFC 5280 §4.1.2.2).
    ///
    /// Profile law: CAs MUST issue positive serial numbers no longer than 20
    /// content octets. Because non-conforming certificates exist in the wild,
    /// users (parsers) SHOULD gracefully handle values that are negative or
    /// longer than 20 octets — so this type preserves whatever INTEGER content
    /// arrives on the wire and exposes the profile judgment separately via
    /// ``isRFC5280Conformant``.
    public struct SerialNumber: Hashable, Sendable {
        /// The big-endian two's-complement content octets of the INTEGER,
        /// exactly as they appear on the wire (minimal DER form).
        public var bytes: ArraySlice<UInt8>

        /// Creates a serial number from raw big-endian two's-complement
        /// content octets.
        ///
        /// The caller is responsible for supplying minimal DER integer form
        /// (no redundant leading `0x00`/`0xFF` octets); non-minimal forms are
        /// rejected at the wire boundary.
        public init(bytes: ArraySlice<UInt8>) {
            self.bytes = bytes
        }

        /// Creates a positive serial number from an unsigned integer value.
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
    }
}

extension RFC_5280.Certificate.SerialNumber {
    /// Whether this value satisfies the §4.1.2.2 CA issuance law:
    /// a positive integer of at most 20 content octets.
    public var isRFC5280Conformant: Bool {
        guard let first = self.bytes.first else { return false }
        guard first & 0x80 == 0 else { return false }
        guard self.bytes.contains(where: { $0 != 0 }) else { return false }
        return self.bytes.count <= 20
    }
}

extension RFC_5280.Certificate.SerialNumber: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        .integer
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        guard node.identifier == identifier else {
            throw ISO_8824.Error.unexpectedFieldType(node.identifier)
        }
        guard case .primitive(let content) = node.content else {
            throw ISO_8824.Error.invalidASN1Object(reason: "CertificateSerialNumber INTEGER must be primitively encoded")
        }
        self.bytes = content
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        coder.appendPrimitiveNode(identifier: identifier) { (bytes: inout [UInt8]) in
            bytes.append(contentsOf: self.bytes)
        }
    }
}

extension RFC_5280.Certificate.SerialNumber: CustomStringConvertible {
    public var description: String {
        self.bytes.map { byte in
            let hex = String(byte, radix: 16)
            return hex.count == 1 ? "0\(hex)" : hex
        }.joined(separator: ":")
    }
}
