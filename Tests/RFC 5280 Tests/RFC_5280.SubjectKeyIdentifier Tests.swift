// RFC_5280.SubjectKeyIdentifier Tests.swift

import ISO_8824
import ISO_8825
import Testing

@testable import RFC_5280

extension RFC_5280.SubjectKeyIdentifier {
    @Suite
    struct Test {
        @Suite struct Unit {}
    }
}

// MARK: - Unit Tests

extension RFC_5280.SubjectKeyIdentifier.Test.Unit {

    // RFC 5280 §4.2.1.2: the value is a bare OCTET STRING
    @Test
    func `Serializes to a bare OCTET STRING`() throws {
        let ski = RFC_5280.SubjectKeyIdentifier(
            keyIdentifier: ISO_8824.OctetString(contentBytes: [0xde, 0xad, 0xbe, 0xef])
        )
        let fixture: [UInt8] = [0x04, 0x04, 0xde, 0xad, 0xbe, 0xef]
        #expect(try derBytes(of: ski) == fixture)
        #expect(try RFC_5280.SubjectKeyIdentifier(derEncoded: fixture) == ski)
    }

    // RFC 5280 §4.2.1.2 bridge law: MUST be non-critical
    @Test
    func `The extension bridge defaults to non-critical`() throws {
        let ski = RFC_5280.SubjectKeyIdentifier(
            keyIdentifier: ISO_8824.OctetString(contentBytes: [0x01, 0x02, 0x03])
        )
        let certificateExtension = try ski.makeExtension()
        #expect(!certificateExtension.critical)
        #expect(certificateExtension.extnID == RFC_5280.Extension.ID.subjectKeyIdentifier)
        // The extnValue OCTET STRING wraps the DER of the value, itself an OCTET STRING.
        #expect(Array(certificateExtension.extnValue.bytes) == [0x04, 0x03, 0x01, 0x02, 0x03])
        #expect(try RFC_5280.SubjectKeyIdentifier(certificateExtension) == ski)
    }
}
