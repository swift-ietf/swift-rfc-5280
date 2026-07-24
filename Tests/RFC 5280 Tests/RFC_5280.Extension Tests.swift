// RFC_5280.Extension Tests.swift

import ISO_8824
import ISO_8825
import Testing

@testable import RFC_5280

extension RFC_5280.Extension {
    @Suite
    struct Test {
        @Suite struct Unit {}
        @Suite struct `Edge Case` {}
    }
}

// MARK: - Unit Tests

extension RFC_5280.Extension.Test.Unit {

    // RFC 5280 §4.2: critical BOOLEAN DEFAULT FALSE
    @Test
    func `A critical extension encodes the boolean`() throws {
        let certificateExtension = RFC_5280.Extension(
            extnID: RFC_5280.Extension.ID.basicConstraints,
            critical: true,
            extnValue: ISO_8824.OctetString(contentBytes: [0x30, 0x00])
        )
        let fixture: [UInt8] = [
            0x30, 0x0c,
            0x06, 0x03, 0x55, 0x1d, 0x13,
            0x01, 0x01, 0xff,
            0x04, 0x02, 0x30, 0x00,
        ]
        #expect(try derBytes(of: certificateExtension) == fixture)
        #expect(try RFC_5280.Extension(derEncoded: fixture) == certificateExtension)
    }

    // DER law: DEFAULT FALSE must be omitted from the encoding
    @Test
    func `A non-critical extension omits the boolean`() throws {
        let certificateExtension = RFC_5280.Extension(
            extnID: RFC_5280.Extension.ID.basicConstraints,
            critical: false,
            extnValue: ISO_8824.OctetString(contentBytes: [0x30, 0x00])
        )
        let fixture: [UInt8] = [
            0x30, 0x09,
            0x06, 0x03, 0x55, 0x1d, 0x13,
            0x04, 0x02, 0x30, 0x00,
        ]
        #expect(try derBytes(of: certificateExtension) == fixture)
        #expect(try RFC_5280.Extension(derEncoded: fixture) == certificateExtension)
    }

    @Test
    func `Extension identifiers carry the RFC 5280 assigned values`() {
        #expect(RFC_5280.Extension.ID.authorityKeyIdentifier.description == "2.5.29.35")
        #expect(RFC_5280.Extension.ID.subjectKeyIdentifier.description == "2.5.29.14")
        #expect(RFC_5280.Extension.ID.keyUsage.description == "2.5.29.15")
        #expect(RFC_5280.Extension.ID.subjectAlternativeName.description == "2.5.29.17")
        #expect(RFC_5280.Extension.ID.basicConstraints.description == "2.5.29.19")
        #expect(RFC_5280.Extension.ID.nameConstraints.description == "2.5.29.30")
        #expect(RFC_5280.Extension.ID.extendedKeyUsage.description == "2.5.29.37")
        #expect(RFC_5280.Extension.ID.authorityInformationAccess.description == "1.3.6.1.5.5.7.1.1")
    }
}

// MARK: - Edge Case Tests

extension RFC_5280.Extension.Test.`Edge Case` {

    // DER law: an encoded DEFAULT value is invalid
    @Test
    func `Rejects an explicitly encoded critical FALSE`() {
        let bytes: [UInt8] = [
            0x30, 0x0c,
            0x06, 0x03, 0x55, 0x1d, 0x13,
            0x01, 0x01, 0x00,
            0x04, 0x02, 0x30, 0x00,
        ]
        #expect(throws: ISO_8824.Error.self) {
            _ = try RFC_5280.Extension(derEncoded: bytes)
        }
    }

    // §4.2 bridge law: a typed decode checks the extension identifier
    @Test
    func `Typed decode rejects a mismatched extnID`() throws {
        let keyUsageExtension = try RFC_5280.KeyUsage(rawValue: 0x8000).makeExtension()
        #expect(throws: ISO_8824.Error.self) {
            _ = try RFC_5280.BasicConstraints(keyUsageExtension)
        }
    }
}
