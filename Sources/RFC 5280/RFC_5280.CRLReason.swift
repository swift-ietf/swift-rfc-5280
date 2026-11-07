public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `CRLReason ::= ENUMERATED { unspecified(0), keyCompromise(1),
    /// cACompromise(2), affiliationChanged(3), superseded(4),
    /// cessationOfOperation(5), certificateHold(6), removeFromCRL(8),
    /// privilegeWithdrawn(9), aACompromise(10) }` (RFC 5280 §5.3.1).
    ///
    /// Note the gap: value 7 is not assigned. Unassigned values are
    /// preserved rather than rejected, so a reader tolerates reason codes
    /// added by later specifications; ``isRFC5280Assigned`` reports whether
    /// the value is one this profile defines.
    ///
    /// Criticality law: conforming CAs MUST mark this extension
    /// non-critical. The `unspecified(0)` value MUST NOT be used — omitting
    /// the extension conveys the same thing.
    public struct CRLReason: Hashable, Sendable, RawRepresentable {
        /// The raw ENUMERATED value carried on the wire.
        public var rawValue: Int

        public init(rawValue: Int) {
            self.rawValue = rawValue
        }
    }
}

extension RFC_5280.CRLReason {
    /// `unspecified(0)` — MUST NOT be used by conforming CAs.
    public static let unspecified = Self(rawValue: 0)

    /// `keyCompromise(1)`.
    public static let keyCompromise = Self(rawValue: 1)

    /// `cACompromise(2)`.
    public static let cACompromise = Self(rawValue: 2)

    /// `affiliationChanged(3)`.
    public static let affiliationChanged = Self(rawValue: 3)

    /// `superseded(4)`.
    public static let superseded = Self(rawValue: 4)

    /// `cessationOfOperation(5)`.
    public static let cessationOfOperation = Self(rawValue: 5)

    /// `certificateHold(6)`.
    public static let certificateHold = Self(rawValue: 6)

    /// `removeFromCRL(8)` — used only in delta CRLs. Value 7 is unassigned.
    public static let removeFromCRL = Self(rawValue: 8)

    /// `privilegeWithdrawn(9)`.
    public static let privilegeWithdrawn = Self(rawValue: 9)

    /// `aACompromise(10)`.
    public static let aACompromise = Self(rawValue: 10)

    /// Whether the raw value is one of the codes RFC 5280 §5.3.1 assigns.
    ///
    /// Value 7 is unassigned, so the assigned set is 0–6 and 8–10.
    public var isRFC5280Assigned: Bool {
        (0...6).contains(self.rawValue) || (8...10).contains(self.rawValue)
    }

    /// Whether this value satisfies §5.3.1: an assigned code other than
    /// `unspecified`, which conforming CAs MUST NOT use.
    public var isRFC5280Conformant: Bool {
        self.isRFC5280Assigned && self != .unspecified
    }
}

extension RFC_5280.CRLReason: CustomStringConvertible {
    public var description: String {
        switch self {
        case .unspecified: "unspecified"
        case .keyCompromise: "keyCompromise"
        case .cACompromise: "cACompromise"
        case .affiliationChanged: "affiliationChanged"
        case .superseded: "superseded"
        case .cessationOfOperation: "cessationOfOperation"
        case .certificateHold: "certificateHold"
        case .removeFromCRL: "removeFromCRL"
        case .privilegeWithdrawn: "privilegeWithdrawn"
        case .aACompromise: "aACompromise"
        case let reason: "CRLReason(rawValue: \(reason.rawValue))"
        }
    }
}

extension RFC_5280.CRLReason: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        .enumerated
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        self.rawValue = try Int(derEncoded: node, withIdentifier: identifier)
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        try self.rawValue.serialize(into: &coder, withIdentifier: identifier)
    }
}

extension RFC_5280.CRLReason {
    /// `id-ce-cRLReasons` (§5.3.1).
    public static var extensionID: ISO_8824.ObjectIdentifier {
        RFC_5280.Extension.ID.reasonCode
    }

    /// Decodes the typed value from a generic ``RFC_5280/Extension``.
    public init(_ certificateExtension: RFC_5280.Extension) throws(ISO_8824.Error) {
        guard certificateExtension.extnID == Self.extensionID else {
            throw ISO_8824.Error.invalidASN1Object(reason: "Expected id-ce-cRLReasons, got \(certificateExtension.extnID)")
        }
        self = try Self(derEncoded: certificateExtension.extnValue.bytes)
    }

    /// Wraps this value as a generic ``RFC_5280/Extension``.
    ///
    /// §5.3.1 criticality law: conforming CAs MUST mark this extension
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
