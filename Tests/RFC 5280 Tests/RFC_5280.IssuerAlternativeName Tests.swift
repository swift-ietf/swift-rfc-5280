// RFC_5280.IssuerAlternativeName Tests.swift

import ISO_8824
import ISO_8825
import Testing

@testable import RFC_5280

extension RFC_5280.IssuerAlternativeName {
    @Suite
    struct Test {
        @Suite struct Unit {}
        @Suite struct `Edge Case` {}
    }
}

// MARK: - Unit Tests

extension RFC_5280.IssuerAlternativeName.Test.Unit {

    // RFC 5280 §4.2.1.7: IssuerAltName ::= GeneralNames
    @Test
    func `A dNSName issuer alternative name round-trips`() throws {
        let names = RFC_5280.IssuerAlternativeName([
            .dNSName(try ISO_8824.IA5String("ca.example.com"))
        ])
        #expect(try roundTrips(names))
    }

    // §4.2.1.7 criticality: SHOULD be non-critical
    @Test
    func `The extension bridge defaults to non-critical`() throws {
        let names = RFC_5280.IssuerAlternativeName([
            .rfc822Name(try ISO_8824.IA5String("ca@example.com"))
        ])
        let certificateExtension = try names.makeExtension()
        #expect(!certificateExtension.critical)
        #expect(certificateExtension.extnID == [2, 5, 29, 18])
        #expect(try RFC_5280.IssuerAlternativeName(certificateExtension) == names)
    }

    // §4.2.1.8: SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF Attribute
    @Test
    func `Subject directory attributes round-trip`() throws {
        let attributes = RFC_5280.SubjectDirectoryAttributes([
            RFC_5280.Attribute(
                type: [2, 5, 4, 6],
                values: [try ISO_8825.`Any`(erasing: try ISO_8824.PrintableString("NL"))]
            )
        ])
        #expect(try roundTrips(attributes))

        // §4.2.1.8 criticality: MUST be non-critical
        let certificateExtension = try attributes.makeExtension()
        #expect(!certificateExtension.critical)
        #expect(certificateExtension.extnID == [2, 5, 29, 9])
        #expect(try RFC_5280.SubjectDirectoryAttributes(certificateExtension) == attributes)
    }

    // An Attribute carries a SET OF values, unlike AttributeTypeAndValue.
    // DER SET OF law: elements are transmitted in ascending encoded-byte
    // order, so a parsed value carries the canonical order, not the order
    // originally supplied.
    @Test
    func `An attribute with several values canonicalises their order`() throws {
        let netherlands = try ISO_8825.`Any`(erasing: try ISO_8824.PrintableString("NL"))
        let belgium = try ISO_8825.`Any`(erasing: try ISO_8824.PrintableString("BE"))

        let unordered = RFC_5280.SubjectDirectoryAttributes([
            RFC_5280.Attribute(type: [2, 5, 4, 6], values: [netherlands, belgium])
        ])
        let reparsed = try RFC_5280.SubjectDirectoryAttributes(derEncoded: try derBytes(of: unordered))
        // "BE" sorts before "NL" by encoded byte value.
        #expect(try #require(reparsed.attributes.first).values == [belgium, netherlands])

        // Already-canonical input is a fixed point of the round-trip.
        #expect(
            try roundTrips(
                RFC_5280.SubjectDirectoryAttributes([
                    RFC_5280.Attribute(type: [2, 5, 4, 6], values: [belgium, netherlands])
                ])
            )
        )
    }
}

// MARK: - Edge Case Tests

extension RFC_5280.IssuerAlternativeName.Test.`Edge Case` {

    // §4.2.1.7: GeneralNames is SEQUENCE SIZE (1..MAX)
    @Test
    func `An empty issuer alternative name is rejected`() {
        #expect(throws: ISO_8824.Error.self) {
            _ = try RFC_5280.IssuerAlternativeName(derEncoded: [0x30, 0x00])
        }
        #expect(throws: ISO_8824.Error.self) {
            _ = try derBytes(of: RFC_5280.IssuerAlternativeName([]))
        }
    }

    // §4.2.1.8: SEQUENCE SIZE (1..MAX)
    @Test
    func `Empty subject directory attributes are rejected`() {
        #expect(throws: ISO_8824.Error.self) {
            _ = try RFC_5280.SubjectDirectoryAttributes(derEncoded: [0x30, 0x00])
        }
        #expect(throws: ISO_8824.Error.self) {
            _ = try derBytes(of: RFC_5280.SubjectDirectoryAttributes([]))
        }
    }
}
