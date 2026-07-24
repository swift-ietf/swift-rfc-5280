// RFC_5280.Time Tests.swift

import ISO_8824
import ISO_8825
import Testing

@testable import RFC_5280

extension RFC_5280.Time {
    @Suite
    struct Test {
        @Suite struct Unit {}
        @Suite struct `Edge Case` {}
    }
}

// MARK: - Unit Tests

extension RFC_5280.Time.Test.Unit {

    // RFC 5280 §4.1.2.5.1: UTCTime "260723120000Z"
    @Test
    func `Parses UTCTime and reserializes identically`() throws {
        let fixture: [UInt8] = [
            0x17, 0x0d,
            0x32, 0x36, 0x30, 0x37, 0x32, 0x33, 0x31, 0x32, 0x30, 0x30, 0x30, 0x30, 0x5a,
        ]
        let time = try RFC_5280.Time(derEncoded: fixture)
        guard case .utcTime = time else {
            Issue.record("Expected the utcTime arm")
            return
        }
        #expect(time.year == 2026)
        #expect(time.month == 7)
        #expect(time.day == 23)
        #expect(time.hours == 12)
        #expect(try derBytes(of: time) == fixture)
    }

    // RFC 5280 §4.1.2.5.2: GeneralizedTime "20500101000000Z"
    @Test
    func `Parses GeneralizedTime and reserializes identically`() throws {
        let fixture: [UInt8] = [
            0x18, 0x0f,
            0x32, 0x30, 0x35, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
        ]
        let time = try RFC_5280.Time(derEncoded: fixture)
        guard case .generalTime = time else {
            Issue.record("Expected the generalTime arm")
            return
        }
        #expect(time.year == 2050)
        #expect(try derBytes(of: time) == fixture)
    }

    // RFC 5280 §4.1.2.5: dates through 2049 MUST be UTCTime
    @Test
    func `Cutover chooses UTCTime through 2049`() throws {
        let time = try RFC_5280.Time(year: 2049, month: 12, day: 31, hours: 23, minutes: 59, seconds: 59)
        guard case .utcTime = time else {
            Issue.record("2049 must encode as UTCTime")
            return
        }
        #expect(time.isRFC5280Conformant)
    }

    // RFC 5280 §4.1.2.5: dates in 2050 or later MUST be GeneralizedTime
    @Test
    func `Cutover chooses GeneralizedTime from 2050`() throws {
        let time = try RFC_5280.Time(year: 2050, month: 1, day: 1, hours: 0, minutes: 0, seconds: 0)
        guard case .generalTime = time else {
            Issue.record("2050 must encode as GeneralizedTime")
            return
        }
        #expect(time.isRFC5280Conformant)
    }

    @Test
    func `Comparable orders across the arms`() throws {
        let before = try RFC_5280.Time(year: 2049, month: 12, day: 31, hours: 23, minutes: 59, seconds: 59)
        let after = try RFC_5280.Time(year: 2050, month: 1, day: 1, hours: 0, minutes: 0, seconds: 0)
        #expect(before < after)
        #expect(!(after < before))
    }
}

// MARK: - Edge Case Tests

extension RFC_5280.Time.Test.`Edge Case` {

    // RFC 5280 §4.1.2.5.1: YY >= 50 is 19YY, YY < 50 is 20YY
    @Test
    func `UTCTime two-digit pivot`() throws {
        let fiftyFixture: [UInt8] = [
            0x17, 0x0d,
            0x35, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
        ]
        #expect(try RFC_5280.Time(derEncoded: fiftyFixture).year == 1950)

        let fortyNineFixture: [UInt8] = [
            0x17, 0x0d,
            0x34, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a,
        ]
        #expect(try RFC_5280.Time(derEncoded: fortyNineFixture).year == 2049)
    }

    @Test
    func `Pre-1950 dates require GeneralizedTime`() throws {
        let time = try RFC_5280.Time(year: 1949, month: 6, day: 1, hours: 0, minutes: 0, seconds: 0)
        guard case .generalTime = time else {
            Issue.record("1949 cannot be represented as UTCTime")
            return
        }
        #expect(time.isRFC5280Conformant)
    }

    // RFC 5280 §4.1.2.5: a GeneralizedTime inside the UTCTime range violates the cutover
    @Test
    func `GeneralizedTime inside the UTCTime range is nonconformant`() throws {
        let time = RFC_5280.Time.generalTime(
            try ISO_8824.GeneralizedTime(year: 2000, month: 1, day: 1, hours: 0, minutes: 0, seconds: 0, fractionalSeconds: 0)
        )
        #expect(!time.isRFC5280Conformant)
    }

    @Test
    func `Rejects a non-time field`() {
        // An INTEGER node is neither UTCTime nor GeneralizedTime.
        #expect(throws: ISO_8824.Error.self) {
            _ = try RFC_5280.Time(derEncoded: [0x02, 0x01, 0x00])
        }
    }
}
