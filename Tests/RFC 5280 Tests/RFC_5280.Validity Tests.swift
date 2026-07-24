// RFC_5280.Validity Tests.swift

import ISO_8824
import ISO_8825
import Testing

@testable import RFC_5280

extension RFC_5280.Validity {
    @Suite
    struct Test {
        @Suite struct Unit {}
        @Suite struct `Edge Case` {}
    }
}

// MARK: - Unit Tests

extension RFC_5280.Validity.Test.Unit {

    @Test
    func `Round-trips a UTCTime interval`() throws {
        let validity = RFC_5280.Validity(
            notBefore: try RFC_5280.Time(year: 2026, month: 7, day: 23, hours: 0, minutes: 0, seconds: 0),
            notAfter: try RFC_5280.Time(year: 2027, month: 7, day: 23, hours: 0, minutes: 0, seconds: 0)
        )
        #expect(try roundTrips(validity))
        #expect(!validity.hasNoWellDefinedExpiration)
    }
}

// MARK: - Edge Case Tests

extension RFC_5280.Validity.Test.`Edge Case` {

    // RFC 5280 §4.1.2.5: no well-defined expiration is 99991231235959Z
    @Test
    func `Recognizes the 9999-12-31 sentinel`() throws {
        let validity = RFC_5280.Validity(
            notBefore: try RFC_5280.Time(year: 2026, month: 1, day: 1, hours: 0, minutes: 0, seconds: 0),
            notAfter: try RFC_5280.Time(year: 9999, month: 12, day: 31, hours: 23, minutes: 59, seconds: 59)
        )
        #expect(validity.hasNoWellDefinedExpiration)
        #expect(try roundTrips(validity))
    }

    @Test
    func `A nearby GeneralizedTime is not the sentinel`() throws {
        let validity = RFC_5280.Validity(
            notBefore: try RFC_5280.Time(year: 2026, month: 1, day: 1, hours: 0, minutes: 0, seconds: 0),
            notAfter: try RFC_5280.Time(year: 9999, month: 12, day: 31, hours: 23, minutes: 59, seconds: 58)
        )
        #expect(!validity.hasNoWellDefinedExpiration)
    }
}
