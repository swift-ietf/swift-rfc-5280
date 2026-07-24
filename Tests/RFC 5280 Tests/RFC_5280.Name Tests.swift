// RFC_5280.Name Tests.swift

import ISO_8824
import ISO_8825
import Testing

@testable import RFC_5280

extension RFC_5280.Name {
    @Suite
    struct Test {
        @Suite struct Unit {}
        @Suite struct `Edge Case` {}
    }
}

// MARK: - Unit Tests

extension RFC_5280.Name.Test.Unit {

    // RFC 5280 §4.1.2.4: CN=Test as a single-RDN name, PrintableString value
    @Test
    func `Serializes CN=Test to the known DER bytes`() throws {
        let name = RFC_5280.Name([
            RFC_5280.RelativeDistinguishedName([
                RFC_5280.AttributeTypeAndValue(
                    type: ISO_8824.ObjectIdentifier.NameAttributes.commonName,
                    value: try ISO_8825.`Any`(erasing: try ISO_8824.PrintableString("Test"))
                )
            ])
        ])
        let fixture: [UInt8] = [
            0x30, 0x0f,
            0x31, 0x0d,
            0x30, 0x0b,
            0x06, 0x03, 0x55, 0x04, 0x03,
            0x13, 0x04, 0x54, 0x65, 0x73, 0x74,
        ]
        #expect(try derBytes(of: name) == fixture)
        #expect(try RFC_5280.Name(derEncoded: fixture) == name)
        #expect(!name.isEmpty)
    }

    @Test
    func `Attribute value reads back as a DirectoryString`() throws {
        let attribute = RFC_5280.AttributeTypeAndValue(
            type: ISO_8824.ObjectIdentifier.NameAttributes.commonName,
            value: try ISO_8825.`Any`(erasing: try ISO_8824.PrintableString("Test"))
        )
        let directoryString = try attribute.directoryStringValue()
        guard case .printableString = directoryString else {
            Issue.record("Expected the printableString arm")
            return
        }
        #expect(directoryString.isRFC5280Preferred)
    }

    @Test
    func `Round-trips a multi-RDN name`() throws {
        let name = RFC_5280.Name([
            RFC_5280.RelativeDistinguishedName([
                RFC_5280.AttributeTypeAndValue(
                    type: ISO_8824.ObjectIdentifier.NameAttributes.countryName,
                    value: try ISO_8825.`Any`(erasing: try ISO_8824.PrintableString("US"))
                )
            ]),
            RFC_5280.RelativeDistinguishedName([
                RFC_5280.AttributeTypeAndValue(
                    type: ISO_8824.ObjectIdentifier.NameAttributes.organizationName,
                    value: try ISO_8825.`Any`(erasing: try ISO_8824.PrintableString("Org"))
                )
            ]),
            RFC_5280.RelativeDistinguishedName([
                RFC_5280.AttributeTypeAndValue(
                    type: ISO_8824.ObjectIdentifier.NameAttributes.commonName,
                    value: try ISO_8825.`Any`(erasing: ISO_8824.UTF8String("Tëst"))
                )
            ]),
        ])
        let bytes = try derBytes(of: name)
        let reparsed = try RFC_5280.Name(derEncoded: bytes)
        #expect(reparsed == name)
        #expect(try derBytes(of: reparsed) == bytes)
    }
}

// MARK: - Edge Case Tests

extension RFC_5280.Name.Test.`Edge Case` {

    // RFC 5280 §4.1.2.4 / X.690 §11.6: SET OF members sort by encoded bytes
    @Test
    func `Multi-valued RDN serializes in canonical SET OF order`() throws {
        let commonName = RFC_5280.AttributeTypeAndValue(
            type: ISO_8824.ObjectIdentifier.NameAttributes.commonName,
            value: try ISO_8825.`Any`(erasing: try ISO_8824.PrintableString("Test"))
        )
        let organization = RFC_5280.AttributeTypeAndValue(
            type: ISO_8824.ObjectIdentifier.NameAttributes.organizationName,
            value: try ISO_8825.`Any`(erasing: try ISO_8824.PrintableString("Org"))
        )
        let oneOrder = try derBytes(of: RFC_5280.RelativeDistinguishedName([commonName, organization]))
        let otherOrder = try derBytes(of: RFC_5280.RelativeDistinguishedName([organization, commonName]))
        #expect(oneOrder == otherOrder)
    }

    // RFC 5280 §4.1.2.4: the empty name is a zero-length RDNSequence
    @Test
    func `The empty name round-trips as an empty sequence`() throws {
        let empty = RFC_5280.Name([])
        #expect(empty.isEmpty)
        #expect(try derBytes(of: empty) == [0x30, 0x00])
        #expect(try RFC_5280.Name(derEncoded: [0x30, 0x00]) == empty)
    }

    // RFC 5280 §4.1.2.4: RelativeDistinguishedName is SET SIZE (1..MAX)
    @Test
    func `An empty RDN is rejected at the wire boundary`() {
        #expect(throws: ISO_8824.Error.self) {
            _ = try RFC_5280.RelativeDistinguishedName(derEncoded: [0x31, 0x00])
        }
    }
}
