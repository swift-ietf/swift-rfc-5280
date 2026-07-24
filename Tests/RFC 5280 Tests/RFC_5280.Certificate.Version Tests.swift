// RFC_5280.Certificate.Version Tests.swift

import Testing

@testable import RFC_5280

extension RFC_5280.Certificate.Version {
    @Suite
    struct Test {
        @Suite struct Unit {}
    }
}

// MARK: - Unit Tests

extension RFC_5280.Certificate.Version.Test.Unit {

    // RFC 5280 §4.1.2.1: Version ::= INTEGER { v1(0), v2(1), v3(2) }
    @Test
    func `The named versions carry their wire values`() {
        #expect(RFC_5280.Certificate.Version.v1.rawValue == 0)
        #expect(RFC_5280.Certificate.Version.v2.rawValue == 1)
        #expect(RFC_5280.Certificate.Version.v3.rawValue == 2)
    }

    @Test
    func `Versions order by wire value`() {
        #expect(RFC_5280.Certificate.Version.v1 < .v2)
        #expect(RFC_5280.Certificate.Version.v2 < .v3)
        #expect(!(RFC_5280.Certificate.Version.v3 < .v3))
    }

    // Unknown wire values are preserved, not rejected: version handling
    // is a certificate-level judgment
    @Test
    func `Unknown raw values are representable and described by value`() {
        let future = RFC_5280.Certificate.Version(rawValue: 3)
        #expect(future > .v3)
        #expect(future.description == "Version(rawValue: 3)")
        #expect(RFC_5280.Certificate.Version.v3.description == "v3")
        #expect(RFC_5280.Certificate.Version.v1.description == "v1")
    }
}
