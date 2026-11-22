// RFC_5280.IssuerAlternativeName Tests.swift

import ISO_8824
import ISO_8825
import Testing

@testable import RFC_5280

enum `IETF.RFC.5280.IssuerAlternativeName Tests` {}

extension `IETF.RFC.5280.IssuerAlternativeName Tests` {
    @Suite
    struct Test {
        @Suite struct Unit {}
        @Suite struct `Edge Case` {}
    }
}

// MARK: - Unit Tests

extension `IETF.RFC.5280.IssuerAlternativeName Tests`.Test.Unit {

    // RFC 5280 §4.2.1.7: IssuerAltName ::= GeneralNames
    @Test
    func `A dNSName issuer alternative name round-trips`() throws {
        let names = IETF.RFC.`5280`.IssuerAlternativeName([
            .dNSName(ISO.`8824`.IA5String("ca.example.com"))
        ])
        #expect(try roundTrips(names))
    }

    // §4.2.1.7 criticality: SHOULD be non-critical
    @Test
    func `The extension bridge defaults to non-critical`() throws {
        let names = IETF.RFC.`5280`.IssuerAlternativeName([
            .rfc822Name(ISO.`8824`.IA5String("ca@example.com"))
        ])
        let certificateExtension = try names.makeExtension()
        #expect(!certificateExtension.critical)
        #expect(certificateExtension.extnID == [2, 5, 29, 18])
        #expect(try IETF.RFC.`5280`.IssuerAlternativeName(certificateExtension) == names)
    }

    // §4.2.1.8: SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF Attribute
    @Test
    func `Subject directory attributes round-trip`() throws {
        let attributes = IETF.RFC.`5280`.SubjectDirectoryAttributes([
            IETF.RFC.`5280`.Attribute(
                type: [2, 5, 4, 6],
                values: [try ISO.`8825`.`Any`(erasing: ISO.`8824`.PrintableString("NL"))]
            )
        ])
        #expect(try roundTrips(attributes))

        // §4.2.1.8 criticality: MUST be non-critical
        let certificateExtension = try attributes.makeExtension()
        #expect(!certificateExtension.critical)
        #expect(certificateExtension.extnID == [2, 5, 29, 9])
        #expect(try IETF.RFC.`5280`.SubjectDirectoryAttributes(certificateExtension) == attributes)
    }

    // An Attribute carries a SET OF values, unlike AttributeTypeAndValue.
    // DER SET OF law: elements are transmitted in ascending encoded-byte
    // order, so a parsed value carries the canonical order, not the order
    // originally supplied.
    @Test
    func `An attribute with several values canonicalises their order`() throws {
        let netherlands = try ISO.`8825`.`Any`(erasing: ISO.`8824`.PrintableString("NL"))
        let belgium = try ISO.`8825`.`Any`(erasing: ISO.`8824`.PrintableString("BE"))

        let unordered = IETF.RFC.`5280`.SubjectDirectoryAttributes([
            IETF.RFC.`5280`.Attribute(type: [2, 5, 4, 6], values: [netherlands, belgium])
        ])
        let reparsed = try IETF.RFC.`5280`.SubjectDirectoryAttributes(derEncoded: try derBytes(of: unordered))
        // "BE" sorts before "NL" by encoded byte value.
        #expect(try #require(reparsed.attributes.first).values == [belgium, netherlands])

        // Already-canonical input is a fixed point of the round-trip.
        #expect(
            try roundTrips(
                IETF.RFC.`5280`.SubjectDirectoryAttributes([
                    IETF.RFC.`5280`.Attribute(type: [2, 5, 4, 6], values: [belgium, netherlands])
                ])
            )
        )
    }
}

// MARK: - Edge Case Tests

extension `IETF.RFC.5280.IssuerAlternativeName Tests`.Test.`Edge Case` {

    // §4.2.1.7: GeneralNames is SEQUENCE SIZE (1..MAX)
    @Test
    func `An empty issuer alternative name is rejected`() {
        #expect(throws: ISO.`8824`.Error.self) {
            _ = try IETF.RFC.`5280`.IssuerAlternativeName(derEncoded: [0x30, 0x00])
        }
        #expect(throws: ISO.`8824`.Error.self) {
            _ = try derBytes(of: IETF.RFC.`5280`.IssuerAlternativeName([]))
        }
    }

    // §4.2.1.8: SEQUENCE SIZE (1..MAX)
    @Test
    func `Empty subject directory attributes are rejected`() {
        #expect(throws: ISO.`8824`.Error.self) {
            _ = try IETF.RFC.`5280`.SubjectDirectoryAttributes(derEncoded: [0x30, 0x00])
        }
        #expect(throws: ISO.`8824`.Error.self) {
            _ = try derBytes(of: IETF.RFC.`5280`.SubjectDirectoryAttributes([]))
        }
    }
}
