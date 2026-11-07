public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `DirectoryString ::= CHOICE { teletexString TeletexString,
    /// printableString PrintableString, universalString UniversalString,
    /// utf8String UTF8String, bmpString BMPString }` (RFC 5280 §4.1.2.4).
    ///
    /// Profile law: CAs conforming to this profile MUST use either
    /// `PrintableString` or `UTF8String` when encoding attributes of type
    /// `DirectoryString` (the TeletexString/BMPString/UniversalString arms
    /// exist to tolerate legacy certificates on parse). New encoders should
    /// use ``printableString(_:)`` when the value fits and
    /// ``utf8String(_:)`` otherwise; ``isRFC5280Preferred`` reports which
    /// arm a parsed value used.
    public enum DirectoryString: Hashable, Sendable {
        case teletexString(ISO_8824.TeletexString)
        case printableString(ISO_8824.PrintableString)
        case universalString(ISO_8824.UniversalString)
        case utf8String(ISO_8824.UTF8String)
        case bmpString(ISO_8824.BMPString)

        /// Whether this value uses one of the two arms the profile permits
        /// new CAs to emit (`PrintableString` or `UTF8String`).
        public var isRFC5280Preferred: Bool {
            switch self {
            case .printableString, .utf8String: true
            case .teletexString, .universalString, .bmpString: false
            }
        }
    }
}

extension RFC_5280.DirectoryString: ISO_8825.DER.Parseable, ISO_8825.DER.Serializable {
    public init(derEncoded node: ISO_8825.Node) throws(ISO_8824.Error) {
        switch node.identifier {
        case ISO_8824.TeletexString.defaultIdentifier:
            self = .teletexString(try ISO_8824.TeletexString(derEncoded: node))
        case ISO_8824.PrintableString.defaultIdentifier:
            self = .printableString(try ISO_8824.PrintableString(derEncoded: node))
        case ISO_8824.UniversalString.defaultIdentifier:
            self = .universalString(try ISO_8824.UniversalString(derEncoded: node))
        case ISO_8824.UTF8String.defaultIdentifier:
            self = .utf8String(try ISO_8824.UTF8String(derEncoded: node))
        case ISO_8824.BMPString.defaultIdentifier:
            self = .bmpString(try ISO_8824.BMPString(derEncoded: node))
        default:
            throw ISO_8824.Error.unexpectedFieldType(node.identifier)
        }
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) {
        switch self {
        case .teletexString(let string):
            try coder.serialize(string)
        case .printableString(let string):
            try coder.serialize(string)
        case .universalString(let string):
            try coder.serialize(string)
        case .utf8String(let string):
            try coder.serialize(string)
        case .bmpString(let string):
            try coder.serialize(string)
        }
    }
}
