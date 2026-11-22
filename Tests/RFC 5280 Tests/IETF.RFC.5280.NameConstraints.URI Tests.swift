// RFC_5280.NameConstraints.URI Tests.swift

import Testing

@testable import RFC_5280

enum `IETF.RFC.5280.NameConstraints.URI Tests` {}

extension `IETF.RFC.5280.NameConstraints.URI Tests` {
    @Suite
    struct Test {
        @Suite struct Unit {}
        @Suite struct `Edge Case` {}
    }
}

// MARK: - Unit Tests

extension `IETF.RFC.5280.NameConstraints.URI Tests`.Test.Unit {

    // RFC 5280 §4.2.1.10: '.example.com' is satisfied by host.example.com
    // and my.host.example.com, but not by example.com
    @Test
    func `The section 4-2-1-10 domain examples hold`() {
        #expect(IETF.RFC.`5280`.NameConstraints.URI.satisfies(host: "host.example.com", constraint: ".example.com"))
        #expect(IETF.RFC.`5280`.NameConstraints.URI.satisfies(host: "my.host.example.com", constraint: ".example.com"))
        #expect(!IETF.RFC.`5280`.NameConstraints.URI.satisfies(host: "example.com", constraint: ".example.com"))
    }

    // A constraint without a leading period specifies a host
    @Test
    func `A host constraint matches exactly one host`() {
        #expect(IETF.RFC.`5280`.NameConstraints.URI.satisfies(host: "host.example.com", constraint: "host.example.com"))
        #expect(!IETF.RFC.`5280`.NameConstraints.URI.satisfies(host: "my.host.example.com", constraint: "host.example.com"))
        #expect(!IETF.RFC.`5280`.NameConstraints.URI.satisfies(host: "example.com", constraint: "host.example.com"))
    }

    @Test
    func `Comparison ignores ASCII case`() {
        #expect(IETF.RFC.`5280`.NameConstraints.URI.satisfies(host: "Host.Example.COM", constraint: "host.example.com"))
        #expect(IETF.RFC.`5280`.NameConstraints.URI.satisfies(host: "a.example.com", constraint: ".EXAMPLE.com"))
    }
}

// MARK: - Edge Case Tests

extension `IETF.RFC.5280.NameConstraints.URI Tests`.Test.`Edge Case` {

    @Test
    func `Empty hosts and empty constraints never match`() {
        #expect(!IETF.RFC.`5280`.NameConstraints.URI.satisfies(host: "", constraint: "host.example.com"))
        #expect(!IETF.RFC.`5280`.NameConstraints.URI.satisfies(host: "host.example.com", constraint: ""))
        #expect(!IETF.RFC.`5280`.NameConstraints.URI.satisfies(host: "", constraint: ""))
    }

    // A domain constraint carries its own label boundary (the leading period),
    // so a same-suffix host with a different label does not match
    @Test
    func `A domain constraint does not match a partial label`() {
        #expect(!IETF.RFC.`5280`.NameConstraints.URI.satisfies(host: "badexample.com", constraint: ".example.com"))
    }
}
