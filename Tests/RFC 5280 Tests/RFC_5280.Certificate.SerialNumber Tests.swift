// RFC_5280.Certificate.SerialNumber Tests.swift

import ISO_8824
import ISO_8825
import Testing

@testable import RFC_5280

enum `RFC_5280.Certificate.SerialNumber Tests` {}

extension `RFC_5280.Certificate.SerialNumber Tests` {
    @Suite
    struct Test {
        @Suite struct Unit {}
        @Suite struct `Edge Case` {}
    }
}

// MARK: - Unit Tests

extension `RFC_5280.Certificate.SerialNumber Tests`.Test.Unit {

    @Test
    func `Encodes an unsigned value in minimal big-endian form`() throws {
        let serial = RFC_5280.Certificate.SerialNumber(UInt64(256))
        #expect(Array(serial.bytes) == [0x01, 0x00])
        #expect(try derBytes(of: serial) == [0x02, 0x02, 0x01, 0x00])
        #expect(serial.isRFC5280Conformant)
    }

    @Test
    func `Pads a high-bit leading octet to stay positive`() {
        let serial = RFC_5280.Certificate.SerialNumber(UInt64(0x80))
        #expect(Array(serial.bytes) == [0x00, 0x80])
        #expect(serial.isRFC5280Conformant)
    }

    @Test
    func `Round-trips through DER`() throws {
        let serial = RFC_5280.Certificate.SerialNumber(UInt64(0x0123_4567_89ab_cdef))
        #expect(try roundTrips(serial))
    }
}

// MARK: - Edge Case Tests

extension `RFC_5280.Certificate.SerialNumber Tests`.Test.`Edge Case` {

    // RFC 5280 §4.1.2.2: serial numbers MUST be positive
    @Test
    func `Negative values are nonconformant but preserved`() throws {
        let fixture: [UInt8] = [0x02, 0x01, 0xff]
        let serial = try RFC_5280.Certificate.SerialNumber(derEncoded: fixture)
        #expect(!serial.isRFC5280Conformant)
        #expect(try derBytes(of: serial) == fixture)
    }

    // RFC 5280 §4.1.2.2: zero is not a positive integer
    @Test
    func `Zero is nonconformant`() {
        let serial = RFC_5280.Certificate.SerialNumber(UInt64(0))
        #expect(Array(serial.bytes) == [0x00])
        #expect(!serial.isRFC5280Conformant)
    }

    // RFC 5280 §4.1.2.2: no longer than 20 octets
    @Test
    func `Values longer than 20 octets are nonconformant but preserved`() throws {
        let content = [UInt8](repeating: 0x7f, count: 21)
        let serial = RFC_5280.Certificate.SerialNumber(bytes: content[...])
        #expect(!serial.isRFC5280Conformant)

        let twenty = RFC_5280.Certificate.SerialNumber(bytes: [UInt8](repeating: 0x7f, count: 20)[...])
        #expect(twenty.isRFC5280Conformant)
    }
}
