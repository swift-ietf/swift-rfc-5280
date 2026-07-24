// RFC_5280.AlgorithmIdentifier Tests.swift

import ISO_8824
import ISO_8825
import Testing

@testable import RFC_5280

extension RFC_5280.AlgorithmIdentifier {
    @Suite
    struct Test {
        @Suite struct Unit {}
        @Suite struct `Edge Case` {}
    }
}

// MARK: - Unit Tests

extension RFC_5280.AlgorithmIdentifier.Test.Unit {

    // RFC 4055 §5: sha256WithRSAEncryption carries an explicit NULL parameter
    @Test
    func `Parses sha256WithRSAEncryption with NULL parameters`() throws {
        let fixture: [UInt8] = [
            0x30, 0x0d,
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
            0x05, 0x00,
        ]
        let identifier = try RFC_5280.AlgorithmIdentifier(derEncoded: fixture)
        #expect(identifier.algorithm == [1, 2, 840, 113549, 1, 1, 11])
        #expect(identifier.parameters != nil)
        #expect(try derBytes(of: identifier) == fixture)
    }

    // RFC 5758 §3.2: ecdsa-with-SHA256 omits the parameters field entirely
    @Test
    func `Parses ecdsa-with-SHA256 with absent parameters`() throws {
        let fixture: [UInt8] = [
            0x30, 0x0a,
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
        ]
        let identifier = try RFC_5280.AlgorithmIdentifier(derEncoded: fixture)
        #expect(identifier.algorithm == [1, 2, 840, 10045, 4, 3, 2])
        #expect(identifier.parameters == nil)
        #expect(try derBytes(of: identifier) == fixture)
    }
}

// MARK: - Edge Case Tests

extension RFC_5280.AlgorithmIdentifier.Test.`Edge Case` {

    // Wire fidelity: NULL parameters and absent parameters are distinct encodings
    @Test
    func `NULL and absent parameters are distinct values`() throws {
        let algorithm: ISO_8824.ObjectIdentifier = [1, 2, 840, 113549, 1, 1, 11]
        let withNull = RFC_5280.AlgorithmIdentifier(
            algorithm: algorithm,
            parameters: try ISO_8825.`Any`(erasing: ISO_8824.Null())
        )
        let absent = RFC_5280.AlgorithmIdentifier(algorithm: algorithm)
        #expect(withNull != absent)
        #expect(try derBytes(of: withNull) != derBytes(of: absent))
        #expect(try roundTrips(withNull))
        #expect(try roundTrips(absent))
    }
}
