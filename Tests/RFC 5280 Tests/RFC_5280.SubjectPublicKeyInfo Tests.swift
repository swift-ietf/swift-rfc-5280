// RFC_5280.SubjectPublicKeyInfo Tests.swift

import ISO_8824
import ISO_8825
import Testing

@testable import RFC_5280

enum `RFC_5280.SubjectPublicKeyInfo Tests` {}

extension `RFC_5280.SubjectPublicKeyInfo Tests` {
    @Suite
    struct Test {
        @Suite struct Unit {}
    }
}

// MARK: - Unit Tests

extension `RFC_5280.SubjectPublicKeyInfo Tests`.Test.Unit {

    // RFC 5480 §2: id-ecPublicKey with a named-curve parameter
    @Test
    func `Round-trips an EC subject public key info`() throws {
        let spki = RFC_5280.SubjectPublicKeyInfo(
            algorithm: RFC_5280.AlgorithmIdentifier(
                algorithm: [1, 2, 840, 10045, 2, 1],
                parameters: try ISO_8825.`Any`(erasing: [1, 2, 840, 10045, 3, 1, 7] as ISO_8824.ObjectIdentifier)
            ),
            subjectPublicKey: try ISO_8824.BitString(bytes: [0x04, 0x01, 0x02, 0x03], paddingBits: 0)
        )
        #expect(try roundTrips(spki))
    }
}
