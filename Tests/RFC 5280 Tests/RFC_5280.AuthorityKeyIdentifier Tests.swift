// RFC_5280.AuthorityKeyIdentifier Tests.swift

import ISO_8824
import ISO_8825
import Testing

@testable import RFC_5280

enum `RFC_5280.AuthorityKeyIdentifier Tests` {}

extension `RFC_5280.AuthorityKeyIdentifier Tests` {
    @Suite
    struct Test {
        @Suite struct Unit {}
        @Suite struct `Edge Case` {}
    }
}

// MARK: - Unit Tests

extension `RFC_5280.AuthorityKeyIdentifier Tests`.Test.Unit {

    // RFC 5280 §4.2.1.1: keyIdentifier is implicitly [0]-tagged
    @Test
    func `Serializes a keyIdentifier-only value to the known DER bytes`() throws {
        let aki = RFC_5280.AuthorityKeyIdentifier(
            keyIdentifier: ISO_8824.OctetString(contentBytes: [0x01, 0x02, 0x03, 0x04])
        )
        let fixture: [UInt8] = [0x30, 0x06, 0x80, 0x04, 0x01, 0x02, 0x03, 0x04]
        #expect(try derBytes(of: aki) == fixture)
        #expect(try RFC_5280.AuthorityKeyIdentifier(derEncoded: fixture) == aki)
    }

    @Test
    func `Round-trips all three fields`() throws {
        let aki = RFC_5280.AuthorityKeyIdentifier(
            keyIdentifier: ISO_8824.OctetString(contentBytes: [0xde, 0xad, 0xbe, 0xef]),
            authorityCertIssuer: [.dNSName(try ISO_8824.IA5String("ca.example.com"))],
            authorityCertSerialNumber: RFC_5280.Certificate.SerialNumber(UInt64(5))
        )
        #expect(try roundTrips(aki))
    }

    @Test
    func `An empty value round-trips as an empty SEQUENCE`() throws {
        let aki = RFC_5280.AuthorityKeyIdentifier()
        #expect(try derBytes(of: aki) == [0x30, 0x00])
        #expect(try RFC_5280.AuthorityKeyIdentifier(derEncoded: [0x30, 0x00]) == aki)
    }
}

// MARK: - Edge Case Tests

extension `RFC_5280.AuthorityKeyIdentifier Tests`.Test.`Edge Case` {

    // RFC 5280 §4.2.1.1 bridge law: MUST be non-critical
    @Test
    func `The extension bridge defaults to non-critical`() throws {
        let aki = RFC_5280.AuthorityKeyIdentifier(
            keyIdentifier: ISO_8824.OctetString(contentBytes: [0x01, 0x02])
        )
        let certificateExtension = try aki.makeExtension()
        #expect(!certificateExtension.critical)
        #expect(certificateExtension.extnID == RFC_5280.Extension.ID.authorityKeyIdentifier)
        #expect(try RFC_5280.AuthorityKeyIdentifier(certificateExtension) == aki)
    }
}
