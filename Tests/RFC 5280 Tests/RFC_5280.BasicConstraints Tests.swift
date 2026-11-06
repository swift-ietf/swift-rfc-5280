// RFC_5280.BasicConstraints Tests.swift

import ISO_8824
import ISO_8825
import Testing

@testable import RFC_5280

enum `RFC_5280.BasicConstraints Tests` {}

extension `RFC_5280.BasicConstraints Tests` {
    @Suite
    struct Test {
        @Suite struct Unit {}
        @Suite struct `Edge Case` {}
    }
}

// MARK: - Unit Tests

extension `RFC_5280.BasicConstraints Tests`.Test.Unit {

    // RFC 5280 §4.2.1.9 with DER DEFAULT law: cA FALSE encodes as an empty SEQUENCE
    @Test
    func `An end-entity value encodes as an empty SEQUENCE`() throws {
        let constraints = RFC_5280.BasicConstraints(isCA: false)
        #expect(try derBytes(of: constraints) == [0x30, 0x00])
        #expect(try RFC_5280.BasicConstraints(derEncoded: [0x30, 0x00]) == constraints)
    }

    @Test
    func `A CA without path length encodes the boolean only`() throws {
        let constraints = RFC_5280.BasicConstraints(isCA: true)
        #expect(try derBytes(of: constraints) == [0x30, 0x03, 0x01, 0x01, 0xff])
        #expect(try RFC_5280.BasicConstraints(derEncoded: [0x30, 0x03, 0x01, 0x01, 0xff]) == constraints)
    }

    @Test
    func `A CA with pathLenConstraint zero encodes both fields`() throws {
        let constraints = RFC_5280.BasicConstraints(isCA: true, pathLenConstraint: 0)
        let fixture: [UInt8] = [0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00]
        #expect(try derBytes(of: constraints) == fixture)
        #expect(try RFC_5280.BasicConstraints(derEncoded: fixture) == constraints)
    }
}

// MARK: - Edge Case Tests

extension `RFC_5280.BasicConstraints Tests`.Test.`Edge Case` {

    // DER law: an encoded DEFAULT FALSE is invalid
    @Test
    func `Rejects an explicitly encoded cA FALSE`() {
        #expect(throws: ISO_8824.Error.self) {
            _ = try RFC_5280.BasicConstraints(derEncoded: [0x30, 0x03, 0x01, 0x01, 0x00])
        }
    }

    // RFC 5280 §4.2.1.9: pathLenConstraint is INTEGER (0..MAX)
    @Test
    func `Rejects a negative pathLenConstraint`() {
        #expect(throws: ISO_8824.Error.self) {
            _ = try RFC_5280.BasicConstraints(derEncoded: [0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0xff])
        }
        #expect(throws: ISO_8824.Error.self) {
            _ = try derBytes(of: RFC_5280.BasicConstraints(isCA: true, pathLenConstraint: -1))
        }
    }

    // RFC 5280 §4.2.1.9 bridge law: MUST be critical in CA certificates
    @Test
    func `The extension bridge defaults to critical`() throws {
        let constraints = RFC_5280.BasicConstraints(isCA: true, pathLenConstraint: 3)
        let certificateExtension = try constraints.makeExtension()
        #expect(certificateExtension.critical)
        #expect(certificateExtension.extnID == RFC_5280.Extension.ID.basicConstraints)
        #expect(try RFC_5280.BasicConstraints(certificateExtension) == constraints)
    }
}
