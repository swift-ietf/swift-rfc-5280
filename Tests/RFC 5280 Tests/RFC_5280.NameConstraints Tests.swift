// RFC_5280.NameConstraints Tests.swift

import ISO_8824
import ISO_8825
import Testing

@testable import RFC_5280

extension RFC_5280.NameConstraints {
    @Suite
    struct Test {
        @Suite struct Unit {}
        @Suite struct `Edge Case` {}
    }
}

// MARK: - Unit Tests

extension RFC_5280.NameConstraints.Test.Unit {

    // RFC 5280 §4.2.1.10: a permitted dNSName subtree
    @Test
    func `Serializes a permitted dNSName subtree to the known DER bytes`() throws {
        let constraints = RFC_5280.NameConstraints(
            permittedSubtrees: [
                RFC_5280.GeneralSubtree(base: .dNSName(try ISO_8824.IA5String("example.com")))
            ]
        )
        let fixture: [UInt8] = [
            0x30, 0x11,
            0xa0, 0x0f,
            0x30, 0x0d,
            0x82, 0x0b,
            0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
        ]
        #expect(try derBytes(of: constraints) == fixture)
        #expect(try RFC_5280.NameConstraints(derEncoded: fixture) == constraints)
    }

    @Test
    func `Round-trips permitted and excluded subtrees together`() throws {
        let constraints = RFC_5280.NameConstraints(
            permittedSubtrees: [
                RFC_5280.GeneralSubtree(base: .dNSName(try ISO_8824.IA5String("example.com"))),
                RFC_5280.GeneralSubtree(base: .iPAddress(ISO_8824.OctetString(contentBytes: [10, 0, 0, 0, 255, 0, 0, 0]))),
            ],
            excludedSubtrees: [
                RFC_5280.GeneralSubtree(base: .dNSName(try ISO_8824.IA5String("forbidden.example.com")))
            ]
        )
        #expect(try roundTrips(constraints))
    }

    @Test
    func `Subtrees with default minimum and absent maximum are conformant`() throws {
        let subtree = RFC_5280.GeneralSubtree(base: .dNSName(try ISO_8824.IA5String("example.com")))
        #expect(subtree.isRFC5280Conformant)
        #expect(!RFC_5280.GeneralSubtree(base: subtree.base, minimum: 1).isRFC5280Conformant)
        #expect(!RFC_5280.GeneralSubtree(base: subtree.base, maximum: 2).isRFC5280Conformant)
    }
}

// MARK: - Edge Case Tests

extension RFC_5280.NameConstraints.Test.`Edge Case` {

    // RFC 5280 §4.2.1.10: the extension must not be an empty sequence
    @Test
    func `An empty NameConstraints is rejected at the wire boundary`() {
        #expect(throws: ISO_8824.Error.self) {
            _ = try RFC_5280.NameConstraints(derEncoded: [0x30, 0x00])
        }
        #expect(throws: ISO_8824.Error.self) {
            _ = try derBytes(of: RFC_5280.NameConstraints())
        }
    }

    // A non-default minimum survives a round-trip (wire fidelity beyond the profile)
    @Test
    func `Non-default base distances round-trip`() throws {
        let constraints = RFC_5280.NameConstraints(
            excludedSubtrees: [
                RFC_5280.GeneralSubtree(base: .dNSName(try ISO_8824.IA5String("example.com")), minimum: 1, maximum: 4)
            ]
        )
        #expect(try roundTrips(constraints))
    }

    // Non-conformant base distances are preserved for wire fidelity, so the
    // aggregate predicate is how a fail-closed policy layer reaches them.
    @Test
    func `The aggregate predicate reports non-conformant subtrees`() throws {
        let conformant = RFC_5280.NameConstraints(
            permittedSubtrees: [
                RFC_5280.GeneralSubtree(base: .dNSName(try ISO_8824.IA5String("example.com")))
            ]
        )
        #expect(conformant.isRFC5280Conformant)

        let nonDefaultMinimum = RFC_5280.NameConstraints(
            excludedSubtrees: [
                RFC_5280.GeneralSubtree(
                    base: .dNSName(try ISO_8824.IA5String("example.com")),
                    minimum: 1
                )
            ]
        )
        #expect(!nonDefaultMinimum.isRFC5280Conformant)

        let presentMaximum = RFC_5280.NameConstraints(
            permittedSubtrees: [
                RFC_5280.GeneralSubtree(
                    base: .dNSName(try ISO_8824.IA5String("example.com")),
                    maximum: 4
                )
            ]
        )
        #expect(!presentMaximum.isRFC5280Conformant)
    }

    // RFC 5280 §4.2.1.10 bridge law: MUST be critical
    @Test
    func `The extension bridge defaults to critical`() throws {
        let constraints = RFC_5280.NameConstraints(
            permittedSubtrees: [RFC_5280.GeneralSubtree(base: .dNSName(try ISO_8824.IA5String("example.com")))]
        )
        let certificateExtension = try constraints.makeExtension()
        #expect(certificateExtension.critical)
        #expect(certificateExtension.extnID == RFC_5280.Extension.ID.nameConstraints)
        #expect(try RFC_5280.NameConstraints(certificateExtension) == constraints)
    }
}
