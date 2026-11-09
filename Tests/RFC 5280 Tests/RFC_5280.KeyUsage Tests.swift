// RFC_5280.KeyUsage Tests.swift

import ISO_8824
import ISO_8825
import Testing

@testable import RFC_5280

enum `RFC_5280.KeyUsage Tests` {}

extension `RFC_5280.KeyUsage Tests` {
    @Suite
    struct Test {
        @Suite struct Unit {}
        @Suite struct `Edge Case` {}
    }
}

// MARK: - Unit Tests

extension `RFC_5280.KeyUsage Tests`.Test.Unit {

    // X.690 §11.2.2 named-bit law: encode only through the highest set bit
    @Test
    func `digitalSignature alone encodes as one octet with 7 padding bits`() throws {
        var usage = RFC_5280.KeyUsage()
        usage.digitalSignature = true
        #expect(try derBytes(of: usage) == [0x03, 0x02, 0x07, 0x80])
        #expect(try RFC_5280.KeyUsage(derEncoded: [0x03, 0x02, 0x07, 0x80]) == usage)
    }

    @Test
    func `keyCertSign and cRLSign encode with 1 padding bit`() throws {
        var usage = RFC_5280.KeyUsage()
        usage.keyCertSign = true
        usage.cRLSign = true
        #expect(try derBytes(of: usage) == [0x03, 0x02, 0x01, 0x06])
        let reparsed = try RFC_5280.KeyUsage(derEncoded: [0x03, 0x02, 0x01, 0x06])
        #expect(reparsed.keyCertSign)
        #expect(reparsed.cRLSign)
        #expect(!reparsed.digitalSignature)
    }

    // decipherOnly is named bit 8, forcing a second content octet
    @Test
    func `decipherOnly encodes as two octets with 7 padding bits`() throws {
        var usage = RFC_5280.KeyUsage()
        usage.decipherOnly = true
        #expect(try derBytes(of: usage) == [0x03, 0x03, 0x07, 0x00, 0x80])
        #expect(try RFC_5280.KeyUsage(derEncoded: [0x03, 0x03, 0x07, 0x00, 0x80]) == usage)
    }

    @Test
    func `Each named bit round-trips independently`() throws {
        try (0..<9).forEach { bit throws in
            let usage = RFC_5280.KeyUsage(rawValue: 0x8000 >> bit)
            #expect(try roundTrips(usage), "named bit \(bit)")
        }
    }

    @Test
    func `Accessors map to their named bits`() {
        var usage = RFC_5280.KeyUsage()
        usage.nonRepudiation = true
        #expect(usage.rawValue == 0x4000)
        usage.keyEncipherment = true
        #expect(usage.rawValue == 0x6000)
        usage.nonRepudiation = false
        #expect(usage.rawValue == 0x2000)
        #expect(usage.keyEncipherment)
        usage.dataEncipherment = true
        usage.keyAgreement = true
        usage.encipherOnly = true
        #expect(usage.dataEncipherment && usage.keyAgreement && usage.encipherOnly)
    }
}

// MARK: - Edge Case Tests

extension `RFC_5280.KeyUsage Tests`.Test.`Edge Case` {

    @Test
    func `An all-zero value encodes as an empty BIT STRING`() throws {
        let usage = RFC_5280.KeyUsage()
        #expect(try derBytes(of: usage) == [0x03, 0x01, 0x00])
        #expect(try RFC_5280.KeyUsage(derEncoded: [0x03, 0x01, 0x00]) == usage)
    }

    @Test
    func `Rejects more than two content octets`() {
        #expect(throws: ISO_8824.Error.self) {
            _ = try RFC_5280.KeyUsage(derEncoded: [0x03, 0x04, 0x00, 0x80, 0x00, 0x80])
        }
    }

    // KeyUsage named bits stop at decipherOnly(8)
    @Test
    func `Bits beyond decipherOnly are refused on serialize as on parse`() {
        (9...15).forEach { bit in
            #expect(throws: ISO_8824.Error.self, "bit \(bit)") {
                _ = try derBytes(of: RFC_5280.KeyUsage(rawValue: 0x8000 >> UInt16(bit)))
            }
        }
    }

    // RFC 5280 §4.2.1.3 bridge law: SHOULD be critical
    @Test
    func `The extension bridge defaults to critical`() throws {
        var usage = RFC_5280.KeyUsage()
        usage.digitalSignature = true
        let certificateExtension = try usage.makeExtension()
        #expect(certificateExtension.critical)
        #expect(certificateExtension.extnID == RFC_5280.Extension.ID.keyUsage)
        #expect(try RFC_5280.KeyUsage(certificateExtension) == usage)
    }
}
