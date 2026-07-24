// RFC_5280.Time.swift
// RFC 5280 §4.1.2.5 — Validity: Time
// https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5

public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `Time ::= CHOICE { utcTime UTCTime, generalTime GeneralizedTime }`
    /// (RFC 5280 §4.1.2.5).
    ///
    /// Encoding cutover law: certificate validity dates through the year 2049
    /// MUST be encoded as `UTCTime`; dates in 2050 or later MUST be encoded as
    /// `GeneralizedTime`. `UTCTime` two-digit years are interpreted with the
    /// §4.1.2.5.1 pivot (`YY >= 50` → 19YY, else 20YY), which the
    /// ``ISO_8824/UTCTime`` wire type applies, so a `UTCTime` can only ever
    /// represent 1950–2049. Dates before 1950 therefore also require
    /// `GeneralizedTime`.
    ///
    /// `GeneralizedTime` values MUST be expressed in Greenwich Mean Time
    /// (`Z` suffix), MUST include seconds, and MUST NOT include fractional
    /// seconds (§4.1.2.5.2); ``isRFC5280Conformant`` reports violations of
    /// the cutover and fractional-second laws that survive DER parsing.
    public enum Time: Hashable, Sendable {
        case utcTime(ISO_8824.UTCTime)
        case generalTime(ISO_8824.GeneralizedTime)
    }
}

extension RFC_5280.Time {
    /// Creates the §4.1.2.5-conformant encoding choice for a calendar date:
    /// `UTCTime` for 1950–2049, `GeneralizedTime` otherwise.
    public init(year: Int, month: Int, day: Int, hours: Int, minutes: Int, seconds: Int) throws(ISO_8824.Error) {
        if (1950...2049).contains(year) {
            self = .utcTime(
                try ISO_8824.UTCTime(year: year, month: month, day: day, hours: hours, minutes: minutes, seconds: seconds)
            )
        } else {
            self = .generalTime(
                try ISO_8824.GeneralizedTime(
                    year: year,
                    month: month,
                    day: day,
                    hours: hours,
                    minutes: minutes,
                    seconds: seconds,
                    fractionalSeconds: 0
                )
            )
        }
    }

    public var year: Int {
        switch self {
        case .utcTime(let time): time.year
        case .generalTime(let time): time.year
        }
    }

    public var month: Int {
        switch self {
        case .utcTime(let time): time.month
        case .generalTime(let time): time.month
        }
    }

    public var day: Int {
        switch self {
        case .utcTime(let time): time.day
        case .generalTime(let time): time.day
        }
    }

    public var hours: Int {
        switch self {
        case .utcTime(let time): time.hours
        case .generalTime(let time): time.hours
        }
    }

    public var minutes: Int {
        switch self {
        case .utcTime(let time): time.minutes
        case .generalTime(let time): time.minutes
        }
    }

    public var seconds: Int {
        switch self {
        case .utcTime(let time): time.seconds
        case .generalTime(let time): time.seconds
        }
    }

    /// Fractional seconds of the underlying wire value.
    ///
    /// Always zero for `UTCTime`; nonzero only for legacy `GeneralizedTime`
    /// values that violate §4.1.2.5.2.
    public var fractionalSeconds: Double {
        switch self {
        case .utcTime: 0
        case .generalTime(let time): time.fractionalSeconds
        }
    }

    /// Whether this value satisfies the §4.1.2.5 encoding laws: the
    /// UTCTime/GeneralizedTime cutover, and the prohibition on fractional
    /// seconds in `GeneralizedTime`.
    public var isRFC5280Conformant: Bool {
        switch self {
        case .utcTime:
            // The two-digit pivot restricts UTCTime to 1950–2049, exactly the
            // range the profile assigns it.
            return true
        case .generalTime(let time):
            guard time.rawFractionalSeconds.isEmpty else { return false }
            return !(1950...2049).contains(time.year)
        }
    }
}

extension RFC_5280.Time: Comparable {
    public static func < (lhs: Self, rhs: Self) -> Bool {
        let lhsComponents = [lhs.year, lhs.month, lhs.day, lhs.hours, lhs.minutes, lhs.seconds]
        let rhsComponents = [rhs.year, rhs.month, rhs.day, rhs.hours, rhs.minutes, rhs.seconds]
        if lhsComponents == rhsComponents {
            return lhs.fractionalSeconds < rhs.fractionalSeconds
        }
        return lhsComponents.lexicographicallyPrecedes(rhsComponents)
    }
}

extension RFC_5280.Time: ISO_8825.DER.Parseable, ISO_8825.DER.Serializable {
    public init(derEncoded node: ISO_8825.Node) throws(ISO_8824.Error) {
        switch node.identifier {
        case ISO_8824.UTCTime.defaultIdentifier:
            self = .utcTime(try ISO_8824.UTCTime(derEncoded: node))
        case ISO_8824.GeneralizedTime.defaultIdentifier:
            self = .generalTime(try ISO_8824.GeneralizedTime(derEncoded: node))
        default:
            throw ISO_8824.Error.unexpectedFieldType(node.identifier)
        }
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) {
        switch self {
        case .utcTime(let time):
            try coder.serialize(time)
        case .generalTime(let time):
            try coder.serialize(time)
        }
    }
}
