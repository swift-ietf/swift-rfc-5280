// RFC_5280.GeneralName Tests.swift

import ISO_8824
import ISO_8825
import Testing

@testable import RFC_5280

extension RFC_5280.GeneralName {
    @Suite
    struct Test {
        @Suite struct Unit {}
        @Suite struct `Edge Case` {}
    }
}

// MARK: - Unit Tests

extension RFC_5280.GeneralName.Test.Unit {

    // RFC 5280 §4.2.1.6: dNSName is an implicitly [2]-tagged IA5String
    @Test
    func `dNSName serializes with implicit context tag 2`() throws {
        let name = RFC_5280.GeneralName.dNSName(try ISO_8824.IA5String("example.com"))
        let fixture: [UInt8] = [
            0x82, 0x0b,
            0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
        ]
        #expect(try derBytes(of: name) == fixture)
        #expect(try RFC_5280.GeneralName(derEncoded: fixture) == name)
    }

    // RFC 5280 §4.2.1.6: iPAddress is 4 octets for IPv4, network byte order
    @Test
    func `iPAddress serializes with implicit context tag 7`() throws {
        let name = RFC_5280.GeneralName.iPAddress(ISO_8824.OctetString(contentBytes: [0xc0, 0x00, 0x02, 0x01]))
        let fixture: [UInt8] = [0x87, 0x04, 0xc0, 0x00, 0x02, 0x01]
        #expect(try derBytes(of: name) == fixture)
        #expect(try RFC_5280.GeneralName(derEncoded: fixture) == name)
    }

    // RFC 5280 §4.2.1.6 / Appendix A.2: directoryName takes an explicit tag
    // because Name is a CHOICE
    @Test
    func `directoryName wraps the Name in a constructed explicit tag`() throws {
        let directoryName = RFC_5280.Name([
            RFC_5280.RelativeDistinguishedName([
                RFC_5280.AttributeTypeAndValue(
                    type: ISO_8824.ObjectIdentifier.NameAttributes.commonName,
                    value: try ISO_8825.`Any`(erasing: try ISO_8824.PrintableString("Test"))
                )
            ])
        ])
        let name = RFC_5280.GeneralName.directoryName(directoryName)
        let fixture: [UInt8] = [
            0xa4, 0x11,
            0x30, 0x0f,
            0x31, 0x0d,
            0x30, 0x0b,
            0x06, 0x03, 0x55, 0x04, 0x03,
            0x13, 0x04, 0x54, 0x65, 0x73, 0x74,
        ]
        #expect(try derBytes(of: name) == fixture)
        #expect(try RFC_5280.GeneralName(derEncoded: fixture) == name)
    }

    @Test
    func `All constructed arms round-trip`() throws {
        #expect(try roundTrips(RFC_5280.GeneralName.rfc822Name(try ISO_8824.IA5String("user@example.com"))))
        #expect(try roundTrips(RFC_5280.GeneralName.uniformResourceIdentifier(try ISO_8824.IA5String("https://example.com/"))))
        #expect(try roundTrips(RFC_5280.GeneralName.registeredID([1, 3, 6, 1, 4, 1, 99999])))
        #expect(
            try roundTrips(
                RFC_5280.GeneralName.otherName(
                    RFC_5280.OtherName(
                        typeID: [1, 3, 6, 1, 4, 1, 99999, 1],
                        value: try ISO_8825.`Any`(erasing: ISO_8824.UTF8String("value"))
                    )
                )
            )
        )
        #expect(
            try roundTrips(
                RFC_5280.GeneralName.ediPartyName(
                    RFC_5280.EDIPartyName(
                        nameAssigner: .printableString(try ISO_8824.PrintableString("Assigner")),
                        partyName: .utf8String(ISO_8824.UTF8String("Party"))
                    )
                )
            )
        )
        #expect(
            try roundTrips(
                RFC_5280.GeneralName.ediPartyName(
                    RFC_5280.EDIPartyName(partyName: .utf8String(ISO_8824.UTF8String("Party")))
                )
            )
        )
    }
}

// MARK: - Edge Case Tests

extension RFC_5280.GeneralName.Test.`Edge Case` {

    @Test
    func `Rejects a universal-class node`() {
        #expect(throws: ISO_8824.Error.self) {
            // A bare IA5String without a context tag is not a GeneralName.
            _ = try RFC_5280.GeneralName(derEncoded: [0x16, 0x01, 0x41])
        }
    }

    @Test
    func `Rejects an unknown context tag`() {
        #expect(throws: ISO_8824.Error.self) {
            _ = try RFC_5280.GeneralName(derEncoded: [0x89, 0x01, 0x41])
        }
    }

    // The x400Address arm preserves the encoding opaquely for round-trip fidelity
    @Test
    func `x400Address content is preserved byte-for-byte`() throws {
        // A constructed [3] wrapping an arbitrary SEQUENCE.
        let fixture: [UInt8] = [0xa3, 0x04, 0x30, 0x02, 0x05, 0x00]
        let name = try RFC_5280.GeneralName(derEncoded: fixture)
        guard case .x400Address = name else {
            Issue.record("Expected the x400Address arm")
            return
        }
        #expect(try derBytes(of: name) == fixture)
    }
}
