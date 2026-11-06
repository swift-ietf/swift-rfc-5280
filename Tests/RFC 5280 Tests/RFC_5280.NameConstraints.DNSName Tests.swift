// RFC_5280.NameConstraints.DNSName Tests.swift

import Testing

@testable import RFC_5280

enum `RFC_5280.NameConstraints.DNSName Tests` {}

extension `RFC_5280.NameConstraints.DNSName Tests` {
    @Suite
    struct Test {
        @Suite struct Unit {}
        @Suite struct `Edge Case` {}
    }
}

// MARK: - Unit Tests

extension `RFC_5280.NameConstraints.DNSName Tests`.Test.Unit {

    // RFC 5280 §4.2.1.10: adding zero or more labels to the left satisfies
    @Test
    func `The section 4-2-1-10 examples hold`() {
        #expect(RFC_5280.NameConstraints.DNSName.satisfies("host.example.com", constraint: "host.example.com"))
        #expect(RFC_5280.NameConstraints.DNSName.satisfies("www.host.example.com", constraint: "host.example.com"))
        #expect(!RFC_5280.NameConstraints.DNSName.satisfies("host1.example.com", constraint: "host.example.com"))
    }

    @Test
    func `Matching is a whole-label suffix test`() {
        #expect(RFC_5280.NameConstraints.DNSName.satisfies("example.com", constraint: "example.com"))
        #expect(RFC_5280.NameConstraints.DNSName.satisfies("a.b.example.com", constraint: "example.com"))
        // A non-label-boundary suffix must not match.
        #expect(!RFC_5280.NameConstraints.DNSName.satisfies("badexample.com", constraint: "example.com"))
        #expect(!RFC_5280.NameConstraints.DNSName.satisfies("example.com", constraint: "www.example.com"))
    }

    // RFC 4343: DNS name comparison is ASCII case-insensitive
    @Test
    func `Comparison ignores ASCII case`() {
        #expect(RFC_5280.NameConstraints.DNSName.satisfies("WWW.Example.COM", constraint: "example.com"))
        #expect(RFC_5280.NameConstraints.DNSName.satisfies("www.example.com", constraint: "EXAMPLE.COM"))
    }
}

// MARK: - Edge Case Tests

extension `RFC_5280.NameConstraints.DNSName Tests`.Test.`Edge Case` {

    @Test
    func `An empty constraint is satisfied by every name`() {
        #expect(RFC_5280.NameConstraints.DNSName.satisfies("example.com", constraint: ""))
        #expect(RFC_5280.NameConstraints.DNSName.satisfies("", constraint: ""))
    }

    @Test
    func `A name shorter than the constraint never satisfies it`() {
        #expect(!RFC_5280.NameConstraints.DNSName.satisfies("com", constraint: "example.com"))
        #expect(!RFC_5280.NameConstraints.DNSName.satisfies("", constraint: "example.com"))
    }

    // A-labels are valid RFC 1123 hosts and compare like any other label
    @Test
    func `A-labels participate as ordinary labels`() {
        #expect(RFC_5280.NameConstraints.DNSName.satisfies("xn--bcher-kva.example", constraint: "xn--bcher-kva.example"))
        #expect(!RFC_5280.NameConstraints.DNSName.satisfies("xn--bcher-kva.example", constraint: "xn--bcher-kvab.example"))
    }

    // §4.2.1.10 presumes the RFC 1034/1123 preferred name syntax; a wire
    // value outside it satisfies no constraint
    @Test
    func `A name outside the preferred syntax satisfies nothing`() {
        #expect(!RFC_5280.NameConstraints.DNSName.satisfies("bad_host.example.com", constraint: "example.com"))
        #expect(!RFC_5280.NameConstraints.DNSName.satisfies("example.com", constraint: "bad_host.example.com"))
    }
}
