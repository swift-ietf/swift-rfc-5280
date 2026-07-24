// RFC_5280.DisplayText.swift
// RFC 5280 §4.2.1.4 — Certificate Policies: DisplayText
// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.4

public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `DisplayText ::= CHOICE { ia5String IA5String (SIZE (1..200)),
    /// visibleString VisibleString (SIZE (1..200)), bmpString BMPString
    /// (SIZE (1..200)), utf8String UTF8String (SIZE (1..200)) }`
    /// (RFC 5280 §4.2.1.4).
    ///
    /// Profile law: conforming CAs SHOULD use the `UTF8String` arm, and MUST
    /// NOT encode more than 200 characters. The `IA5String` arm is retained
    /// for compatibility with legacy certificates. Because non-conforming
    /// values exist in the wild, any length that survives DER parsing is
    /// preserved and the profile judgment is reported by
    /// ``isRFC5280Conformant``.
    public enum DisplayText: Hashable, Sendable {
        case ia5String(ISO_8824.IA5String)
        case visibleString(ISO_8824.VisibleString)
        case bmpString(ISO_8824.BMPString)
        case utf8String(ISO_8824.UTF8String)
    }
}

extension RFC_5280.DisplayText {
    /// The encoded content octets of the selected arm.
    ///
    /// The SIZE (1..200) bound counts characters, which equals the octet
    /// count only for the single-octet arms; ``isRFC5280Conformant`` applies
    /// the per-arm rule.
    public var contentBytes: ArraySlice<UInt8> {
        switch self {
        case .ia5String(let text): text.bytes
        case .visibleString(let text): text.bytes
        case .bmpString(let text): text.bytes
        case .utf8String(let text): text.bytes
        }
    }

    /// Whether this value satisfies the §4.2.1.4 SIZE (1..200) bound.
    ///
    /// `BMPString` encodes each character in two octets, so its bound is 400
    /// octets; the other arms are counted in octets directly (UTF-8
    /// multi-byte sequences are counted conservatively by octet).
    public var isRFC5280Conformant: Bool {
        let count = self.contentBytes.count
        guard count >= 1 else { return false }
        switch self {
        case .bmpString: return count <= 400
        case .ia5String, .visibleString, .utf8String: return count <= 200
        }
    }

    /// Whether this value uses the arm the profile tells new CAs to prefer.
    public var isRFC5280Preferred: Bool {
        if case .utf8String = self { return true }
        return false
    }
}

extension RFC_5280.DisplayText: ISO_8825.DER.Parseable, ISO_8825.DER.Serializable {
    public init(derEncoded node: ISO_8825.Node) throws(ISO_8824.Error) {
        switch node.identifier {
        case ISO_8824.IA5String.defaultIdentifier:
            self = .ia5String(try ISO_8824.IA5String(derEncoded: node))
        case ISO_8824.VisibleString.defaultIdentifier:
            self = .visibleString(try ISO_8824.VisibleString(derEncoded: node))
        case ISO_8824.BMPString.defaultIdentifier:
            self = .bmpString(try ISO_8824.BMPString(derEncoded: node))
        case ISO_8824.UTF8String.defaultIdentifier:
            self = .utf8String(try ISO_8824.UTF8String(derEncoded: node))
        default:
            throw ISO_8824.Error.unexpectedFieldType(node.identifier)
        }
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) {
        switch self {
        case .ia5String(let text):
            try coder.serialize(text)
        case .visibleString(let text):
            try coder.serialize(text)
        case .bmpString(let text):
            try coder.serialize(text)
        case .utf8String(let text):
            try coder.serialize(text)
        }
    }
}
