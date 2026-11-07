// RFC_5280.SubjectAlternativeName Tests.swift

import ISO_8824
import ISO_8825
import Testing

@testable import RFC_5280

enum `RFC_5280.SubjectAlternativeName Tests` {}

extension `RFC_5280.SubjectAlternativeName Tests` {
    @Suite
    struct Test {
        @Suite struct Unit {}
        @Suite struct `Edge Case` {}
    }
}

// MARK: - Unit Tests

extension `RFC_5280.SubjectAlternativeName Tests`.Test.Unit {

    // RFC 5280 §4.2.1.6: a single dNSName SAN
    @Test
    func `Serializes a dNSName SAN to the known DER bytes`() throws {
        let san = RFC_5280.SubjectAlternativeName([
            .dNSName(ISO_8824.IA5String("example.com"))
        ])
        let fixture: [UInt8] = [
            0x30, 0x0d,
            0x82, 0x0b,
            0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
        ]
        #expect(try derBytes(of: san) == fixture)
        #expect(try RFC_5280.SubjectAlternativeName(derEncoded: fixture) == san)
    }

    @Test
    func `Round-trips mixed name forms`() throws {
        let san = RFC_5280.SubjectAlternativeName([
            .dNSName(ISO_8824.IA5String("example.com")),
            .dNSName(ISO_8824.IA5String("www.example.com")),
            .iPAddress(ISO_8824.OctetString(contentBytes: [0xc0, 0x00, 0x02, 0x01])),
            .rfc822Name(ISO_8824.IA5String("admin@example.com")),
        ])
        #expect(try roundTrips(san))
    }
}

// MARK: - Edge Case Tests

extension `RFC_5280.SubjectAlternativeName Tests`.Test.`Edge Case` {

    // RFC 5280 §4.2.1.6: GeneralNames is SEQUENCE SIZE (1..MAX)
    @Test
    func `An empty SAN is rejected at the wire boundary`() {
        #expect(throws: ISO_8824.Error.self) {
            _ = try RFC_5280.SubjectAlternativeName(derEncoded: [0x30, 0x00])
        }
        #expect(throws: ISO_8824.Error.self) {
            _ = try derBytes(of: RFC_5280.SubjectAlternativeName([]))
        }
    }

    // RFC 5280 §4.2.1.6 bridge law: SHOULD be non-critical (unless subject is empty)
    @Test
    func `The extension bridge defaults to non-critical`() throws {
        let san = RFC_5280.SubjectAlternativeName([.dNSName(ISO_8824.IA5String("example.com"))])
        let certificateExtension = try san.makeExtension()
        #expect(!certificateExtension.critical)
        #expect(certificateExtension.extnID == RFC_5280.Extension.ID.subjectAlternativeName)
        #expect(try RFC_5280.SubjectAlternativeName(certificateExtension) == san)

        let critical = try san.makeExtension(critical: true)
        #expect(critical.critical)
    }
}
