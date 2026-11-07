// RFC_5280.AuthorityInformationAccess Tests.swift

import ISO_8824
import ISO_8825
import Testing

@testable import RFC_5280

enum `RFC_5280.AuthorityInformationAccess Tests` {}

extension `RFC_5280.AuthorityInformationAccess Tests` {
    @Suite
    struct Test {
        @Suite struct Unit {}
        @Suite struct `Edge Case` {}
    }
}

// MARK: - Unit Tests

extension `RFC_5280.AuthorityInformationAccess Tests`.Test.Unit {

    // RFC 5280 §4.2.2.1: OCSP responder location as a URI
    @Test
    func `Serializes an OCSP access description to the known DER bytes`() throws {
        let aia = RFC_5280.AuthorityInformationAccess([
            RFC_5280.AccessDescription(
                accessMethod: RFC_5280.AccessDescription.ID.ocsp,
                accessLocation: .uniformResourceIdentifier(ISO_8824.IA5String("http://ocsp.example.com"))
            )
        ])
        let fixture: [UInt8] = [
            0x30, 0x25,
            0x30, 0x23,
            0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01,
            0x86, 0x17,
            0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x6f, 0x63, 0x73, 0x70,
            0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
        ]
        #expect(try derBytes(of: aia) == fixture)
        #expect(try RFC_5280.AuthorityInformationAccess(derEncoded: fixture) == aia)
    }

    @Test
    func `Access methods carry the RFC 5280 assigned values`() {
        #expect(RFC_5280.AccessDescription.ID.ocsp.description == "1.3.6.1.5.5.7.48.1")
        #expect(RFC_5280.AccessDescription.ID.caIssuers.description == "1.3.6.1.5.5.7.48.2")
    }

    @Test
    func `Round-trips OCSP and caIssuers together`() throws {
        let aia = RFC_5280.AuthorityInformationAccess([
            RFC_5280.AccessDescription(
                accessMethod: RFC_5280.AccessDescription.ID.ocsp,
                accessLocation: .uniformResourceIdentifier(ISO_8824.IA5String("http://ocsp.example.com"))
            ),
            RFC_5280.AccessDescription(
                accessMethod: RFC_5280.AccessDescription.ID.caIssuers,
                accessLocation: .uniformResourceIdentifier(ISO_8824.IA5String("http://ca.example.com/issuers"))
            ),
        ])
        #expect(try roundTrips(aia))
    }
}

// MARK: - Edge Case Tests

extension `RFC_5280.AuthorityInformationAccess Tests`.Test.`Edge Case` {

    // RFC 5280 §4.2.2.1: SEQUENCE SIZE (1..MAX)
    @Test
    func `An empty AIA is rejected at the wire boundary`() {
        #expect(throws: ISO_8824.Error.self) {
            _ = try RFC_5280.AuthorityInformationAccess(derEncoded: [0x30, 0x00])
        }
        #expect(throws: ISO_8824.Error.self) {
            _ = try derBytes(of: RFC_5280.AuthorityInformationAccess([]))
        }
    }

    // RFC 5280 §4.2.2.1 bridge law: MUST be non-critical
    @Test
    func `The extension bridge defaults to non-critical`() throws {
        let aia = RFC_5280.AuthorityInformationAccess([
            RFC_5280.AccessDescription(
                accessMethod: RFC_5280.AccessDescription.ID.ocsp,
                accessLocation: .uniformResourceIdentifier(ISO_8824.IA5String("http://ocsp.example.com"))
            )
        ])
        let certificateExtension = try aia.makeExtension()
        #expect(!certificateExtension.critical)
        #expect(certificateExtension.extnID == RFC_5280.Extension.ID.authorityInformationAccess)
        #expect(try RFC_5280.AuthorityInformationAccess(certificateExtension) == aia)
    }
}
