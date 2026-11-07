extension RFC_5280.Certificate {
    /// `Version ::= INTEGER { v1(0), v2(1), v3(2) }` (RFC 5280 §4.1.2.1).
    ///
    /// Profile law: when extensions are present the version MUST be v3; when
    /// unique identifiers are present without extensions the version SHOULD be
    /// v2; otherwise the version MUST be v1. On the wire the field is
    /// `[0] EXPLICIT` tagged with `DEFAULT v1`, so a conforming DER encoder
    /// omits the field entirely for v1 — ``RFC_5280/TBSCertificate`` owns that
    /// tagging law.
    public struct Version: Hashable, Sendable, RawRepresentable, Comparable {
        /// The raw INTEGER value carried on the wire (`v1` = 0, `v2` = 1, `v3` = 2).
        public var rawValue: Int

        public init(rawValue: Int) {
            self.rawValue = rawValue
        }
    }
}

extension RFC_5280.Certificate.Version {
    /// X.509 version 1 (wire value 0).
    public static let v1 = Self(rawValue: 0)

    /// X.509 version 2 (wire value 1).
    public static let v2 = Self(rawValue: 1)

    /// X.509 version 3 (wire value 2).
    public static let v3 = Self(rawValue: 2)

    public static func < (lhs: Self, rhs: Self) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

extension RFC_5280.Certificate.Version: CustomStringConvertible {
    public var description: String {
        switch self.rawValue {
        case 0: "v1"
        case 1: "v2"
        case 2: "v3"
        case let raw: "Version(rawValue: \(raw))"
        }
    }
}
