// RFC_5280.PolicyConstraints Tests.swift

import ISO_8824
import ISO_8825
import Testing

@testable import RFC_5280

enum `RFC_5280.PolicyConstraints Tests` {}

extension `RFC_5280.PolicyConstraints Tests` {
    @Suite
    struct Test {
        @Suite struct Unit {}
        @Suite struct `Edge Case` {}
    }
}

// MARK: - Unit Tests

extension `RFC_5280.PolicyConstraints Tests`.Test.Unit {

    // RFC 5280 §4.2.1.11: both fields are implicitly tagged SkipCerts
    @Test
    func `requireExplicitPolicy serializes to the known DER bytes`() throws {
        let constraints = RFC_5280.PolicyConstraints(requireExplicitPolicy: 0)
        // SEQUENCE { [0] IMPLICIT INTEGER 0 }
        let fixture: [UInt8] = [0x30, 0x03, 0x80, 0x01, 0x00]
        #expect(try derBytes(of: constraints) == fixture)
        #expect(try RFC_5280.PolicyConstraints(derEncoded: fixture) == constraints)
    }

    @Test
    func `inhibitPolicyMapping uses context tag 1`() throws {
        let constraints = RFC_5280.PolicyConstraints(inhibitPolicyMapping: 1)
        let fixture: [UInt8] = [0x30, 0x03, 0x81, 0x01, 0x01]
        #expect(try derBytes(of: constraints) == fixture)
        #expect(try RFC_5280.PolicyConstraints(derEncoded: fixture) == constraints)
    }

    @Test
    func `Both fields together round-trip`() throws {
        #expect(try roundTrips(RFC_5280.PolicyConstraints(requireExplicitPolicy: 2, inhibitPolicyMapping: 3)))
    }

    // §4.2.1.11 criticality: MUST be critical
    @Test
    func `The extension bridge defaults to critical`() throws {
        let constraints = RFC_5280.PolicyConstraints(requireExplicitPolicy: 0)
        let certificateExtension = try constraints.makeExtension()
        #expect(certificateExtension.critical)
        #expect(certificateExtension.extnID == [2, 5, 29, 36])
        #expect(try RFC_5280.PolicyConstraints(certificateExtension) == constraints)
    }
}

// MARK: - Edge Case Tests

extension `RFC_5280.PolicyConstraints Tests`.Test.`Edge Case` {

    // §4.2.1.11: conforming CAs MUST NOT issue an empty policy constraints
    @Test
    func `An empty PolicyConstraints is rejected at the wire boundary`() {
        #expect(throws: ISO_8824.Error.self) {
            _ = try RFC_5280.PolicyConstraints(derEncoded: [0x30, 0x00])
        }
        #expect(throws: ISO_8824.Error.self) {
            _ = try derBytes(of: RFC_5280.PolicyConstraints())
        }
    }

    // SkipCerts ::= INTEGER (0..MAX)
    @Test
    func `A negative SkipCerts is rejected`() {
        #expect(throws: ISO_8824.Error.self) {
            _ = try derBytes(of: RFC_5280.PolicyConstraints(requireExplicitPolicy: -1))
        }
        // [0] IMPLICIT INTEGER -1
        #expect(throws: ISO_8824.Error.self) {
            _ = try RFC_5280.PolicyConstraints(derEncoded: [0x30, 0x03, 0x80, 0x01, 0xFF])
        }
    }
}
