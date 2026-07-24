// RFC_5280.NameConstraints.IPAddress Tests.swift

import ISO_8824
import RFC_4291
import RFC_791
import Testing

@testable import RFC_5280

extension RFC_5280.NameConstraints.IPAddress {
    @Suite
    struct Test {
        @Suite struct Unit {}
        @Suite struct `Edge Case` {}
    }
}

// MARK: - Unit Tests

extension RFC_5280.NameConstraints.IPAddress.Test.Unit {

    // RFC 5280 §4.2.1.10: 8 octets for an IPv4 range, base then mask
    @Test
    func `Splits an IPv4 constraint into base and mask halves`() throws {
        let range = try RFC_5280.NameConstraints.IPAddress(
            constraint: ISO_8824.OctetString(contentBytes: [10, 0, 0, 0, 255, 0, 0, 0])
        )
        #expect(range == .v4(base: RFC_791.IPv4.Address(10, 0, 0, 0), mask: RFC_791.IPv4.Address(255, 0, 0, 0)))
        #expect(range.isIPv4)
        #expect(range.prefixLength == 8)
    }

    @Test
    func `Contains masks the address before comparing`() throws {
        let range = try RFC_5280.NameConstraints.IPAddress(
            constraint: ISO_8824.OctetString(contentBytes: [192, 0, 2, 0, 255, 255, 255, 0])
        )
        #expect(range.contains(RFC_791.IPv4.Address(192, 0, 2, 1)))
        #expect(range.contains([192, 0, 2, 255]))
        #expect(!range.contains(RFC_791.IPv4.Address(192, 0, 3, 1)))
    }

    @Test
    func `An IPv6 constraint takes 32 octets`() throws {
        var constraint = [UInt8](repeating: 0, count: 32)
        constraint[0] = 0x20
        constraint[1] = 0x01
        constraint[2] = 0x0d
        constraint[3] = 0xb8
        constraint.replaceSubrange(16..<20, with: repeatElement(0xFF, count: 4))
        let range = try RFC_5280.NameConstraints.IPAddress(
            constraint: ISO_8824.OctetString(contentBytes: constraint[...])
        )
        #expect(!range.isIPv4)
        #expect(range.prefixLength == 32)
        var address = [UInt8](repeating: 0, count: 16)
        address[0] = 0x20
        address[1] = 0x01
        address[2] = 0x0d
        address[3] = 0xb8
        address[15] = 1
        #expect(range.contains(address[...]))
        address[0] = 0x30
        #expect(!range.contains(address[...]))
    }
}

// MARK: - Edge Case Tests

extension RFC_5280.NameConstraints.IPAddress.Test.`Edge Case` {

    // RFC 5280 §4.2.1.10 length law
    @Test
    func `Rejects constraint lengths other than 8 and 32`() {
        #expect(throws: ISO_8824.Error.self) {
            _ = try RFC_5280.NameConstraints.IPAddress(
                constraint: ISO_8824.OctetString(contentBytes: [10, 0, 0, 0])
            )
        }
        #expect(throws: ISO_8824.Error.self) {
            _ = try RFC_5280.NameConstraints.IPAddress(
                constraint: ISO_8824.OctetString(contentBytes: [10, 0, 0, 0, 255, 0, 0, 0, 0])
            )
        }
    }

    @Test
    func `An address of the wrong family never matches`() throws {
        let range = try RFC_5280.NameConstraints.IPAddress(
            constraint: ISO_8824.OctetString(contentBytes: [10, 0, 0, 0, 255, 0, 0, 0])
        )
        #expect(!range.contains(ArraySlice([UInt8](repeating: 0, count: 16))))
        #expect(!range.contains(RFC_4291.IPv6.Address.loopback))
        #expect(!range.contains([]))
    }

    // RFC 4632 style requires contiguous masks; wire fidelity preserves others
    @Test
    func `Non-contiguous masks are preserved but reported non-conformant`() {
        let range = RFC_5280.NameConstraints.IPAddress.v4(
            base: RFC_791.IPv4.Address(10, 0, 0, 0),
            mask: RFC_791.IPv4.Address(255, 0, 255, 0)
        )
        #expect(!range.isCIDRConformant)
        #expect(range.prefixLength == nil)
        // Matching still applies the mask literally.
        #expect(range.contains(RFC_791.IPv4.Address(10, 99, 0, 42)))
        #expect(!range.contains(RFC_791.IPv4.Address(10, 99, 1, 42)))
    }

    @Test
    func `Partial-byte contiguous masks are conformant`() {
        let range = RFC_5280.NameConstraints.IPAddress.v4(
            base: RFC_791.IPv4.Address(10, 0, 0, 0),
            mask: RFC_791.IPv4.Address(255, 224, 0, 0)
        )
        #expect(range.isCIDRConformant)
        #expect(range.prefixLength == 11)
        let nonContiguous = RFC_5280.NameConstraints.IPAddress.v4(
            base: RFC_791.IPv4.Address(10, 0, 0, 0),
            mask: RFC_791.IPv4.Address(255, 160, 0, 0)
        )
        #expect(!nonContiguous.isCIDRConformant)
    }

    @Test
    func `The all-zeros and all-ones masks are conformant`() {
        #expect(
            RFC_5280.NameConstraints.IPAddress.v4(
                base: RFC_791.IPv4.Address(0, 0, 0, 0),
                mask: RFC_791.IPv4.Address(0, 0, 0, 0)
            ).prefixLength == 0
        )
        #expect(
            RFC_5280.NameConstraints.IPAddress.v4(
                base: RFC_791.IPv4.Address(10, 0, 0, 1),
                mask: RFC_791.IPv4.Address(255, 255, 255, 255)
            ).prefixLength == 32
        )
    }

    // An IPv6 mask whose one-bits resume after a zero-bit is not CIDR
    @Test
    func `IPv6 contiguity is judged across all segments`() throws {
        var octets = [UInt8](repeating: 0, count: 32)
        // base ::, mask ff00::ff00:0:0:0 — ones resuming after zeros.
        octets[16] = 0xFF
        octets[24] = 0xFF
        let range = try RFC_5280.NameConstraints.IPAddress(
            constraint: ISO_8824.OctetString(contentBytes: octets[...])
        )
        #expect(!range.isCIDRConformant)
        #expect(range.prefixLength == nil)
    }
}
