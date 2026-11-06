// RFC_5280.ExtendedKeyUsage Tests.swift

import ISO_8824
import ISO_8825
import Testing

@testable import RFC_5280

enum `RFC_5280.ExtendedKeyUsage Tests` {}

extension `RFC_5280.ExtendedKeyUsage Tests` {
    @Suite
    struct Test {
        @Suite struct Unit {}
        @Suite struct `Edge Case` {}
    }
}

// MARK: - Unit Tests

extension `RFC_5280.ExtendedKeyUsage Tests`.Test.Unit {

    // RFC 5280 §4.2.1.12: id-kp-serverAuth + id-kp-clientAuth
    @Test
    func `Serializes serverAuth and clientAuth to the known DER bytes`() throws {
        let usage = RFC_5280.ExtendedKeyUsage([
            RFC_5280.ExtendedKeyUsage.ID.serverAuth,
            RFC_5280.ExtendedKeyUsage.ID.clientAuth,
        ])
        let fixture: [UInt8] = [
            0x30, 0x14,
            0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01,
            0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02,
        ]
        #expect(try derBytes(of: usage) == fixture)
        #expect(try RFC_5280.ExtendedKeyUsage(derEncoded: fixture) == usage)
    }

    @Test
    func `Key purposes carry the RFC 5280 assigned values`() {
        #expect(RFC_5280.ExtendedKeyUsage.ID.anyExtendedKeyUsage.description == "2.5.29.37.0")
        #expect(RFC_5280.ExtendedKeyUsage.ID.serverAuth.description == "1.3.6.1.5.5.7.3.1")
        #expect(RFC_5280.ExtendedKeyUsage.ID.clientAuth.description == "1.3.6.1.5.5.7.3.2")
        #expect(RFC_5280.ExtendedKeyUsage.ID.codeSigning.description == "1.3.6.1.5.5.7.3.3")
        #expect(RFC_5280.ExtendedKeyUsage.ID.emailProtection.description == "1.3.6.1.5.5.7.3.4")
        #expect(RFC_5280.ExtendedKeyUsage.ID.timeStamping.description == "1.3.6.1.5.5.7.3.8")
        #expect(RFC_5280.ExtendedKeyUsage.ID.ocspSigning.description == "1.3.6.1.5.5.7.3.9")
    }
}

// MARK: - Edge Case Tests

extension `RFC_5280.ExtendedKeyUsage Tests`.Test.`Edge Case` {

    // RFC 5280 §4.2.1.12: SEQUENCE SIZE (1..MAX)
    @Test
    func `An empty sequence is rejected at the wire boundary`() {
        #expect(throws: ISO_8824.Error.self) {
            _ = try RFC_5280.ExtendedKeyUsage(derEncoded: [0x30, 0x00])
        }
        #expect(throws: ISO_8824.Error.self) {
            _ = try derBytes(of: RFC_5280.ExtendedKeyUsage([]))
        }
    }

    // RFC 5280 §4.2.1.12 bridge law: criticality is at the CA's discretion
    @Test
    func `The extension bridge defaults to non-critical`() throws {
        let usage = RFC_5280.ExtendedKeyUsage([RFC_5280.ExtendedKeyUsage.ID.serverAuth])
        let certificateExtension = try usage.makeExtension()
        #expect(!certificateExtension.critical)
        #expect(certificateExtension.extnID == RFC_5280.Extension.ID.extendedKeyUsage)
        #expect(try RFC_5280.ExtendedKeyUsage(certificateExtension) == usage)
    }
}
