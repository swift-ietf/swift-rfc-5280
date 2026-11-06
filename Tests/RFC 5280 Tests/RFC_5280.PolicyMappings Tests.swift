// RFC_5280.PolicyMappings Tests.swift

import ISO_8824
import ISO_8825
import Testing

@testable import RFC_5280

enum `RFC_5280.PolicyMappings Tests` {}

extension `RFC_5280.PolicyMappings Tests` {
    @Suite
    struct Test {
        @Suite struct Unit {}
        @Suite struct `Edge Case` {}
    }
}

private let issuerPolicy: ISO_8824.ObjectIdentifier = [2, 16, 840, 1, 101, 3, 2, 1, 48, 1]
private let subjectPolicy: ISO_8824.ObjectIdentifier = [2, 16, 840, 1, 101, 3, 2, 1, 48, 2]

// MARK: - Unit Tests

extension `RFC_5280.PolicyMappings Tests`.Test.Unit {

    @Test
    func `A mapping pair round-trips`() throws {
        let mappings = RFC_5280.PolicyMappings([
            RFC_5280.PolicyMappings.Mapping(
                issuerDomainPolicy: issuerPolicy,
                subjectDomainPolicy: subjectPolicy
            )
        ])
        #expect(try roundTrips(mappings))
    }

    // §4.2.1.5 criticality: SHOULD be critical
    @Test
    func `The extension bridge defaults to critical`() throws {
        let mappings = RFC_5280.PolicyMappings([
            RFC_5280.PolicyMappings.Mapping(
                issuerDomainPolicy: issuerPolicy,
                subjectDomainPolicy: subjectPolicy
            )
        ])
        let certificateExtension = try mappings.makeExtension()
        #expect(certificateExtension.critical)
        #expect(certificateExtension.extnID == [2, 5, 29, 33])
        #expect(try RFC_5280.PolicyMappings(certificateExtension) == mappings)
    }

    // §4.2.1.14: InhibitAnyPolicy is a bare SkipCerts INTEGER
    @Test
    func `InhibitAnyPolicy encodes as a bare integer`() throws {
        let inhibit = RFC_5280.InhibitAnyPolicy(skipCerts: 1)
        #expect(try derBytes(of: inhibit) == [0x02, 0x01, 0x01])
        #expect(try RFC_5280.InhibitAnyPolicy(derEncoded: [0x02, 0x01, 0x01]) == inhibit)

        // §4.2.1.14 criticality: MUST be critical
        let certificateExtension = try inhibit.makeExtension()
        #expect(certificateExtension.critical)
        #expect(certificateExtension.extnID == [2, 5, 29, 54])
        #expect(try RFC_5280.InhibitAnyPolicy(certificateExtension) == inhibit)
    }
}

// MARK: - Edge Case Tests

extension `RFC_5280.PolicyMappings Tests`.Test.`Edge Case` {

    // §4.2.1.5: SEQUENCE SIZE (1..MAX)
    @Test
    func `An empty mapping sequence is rejected`() {
        #expect(throws: ISO_8824.Error.self) {
            _ = try RFC_5280.PolicyMappings(derEncoded: [0x30, 0x00])
        }
        #expect(throws: ISO_8824.Error.self) {
            _ = try derBytes(of: RFC_5280.PolicyMappings([]))
        }
    }

    // §4.2.1.5: policies must not be mapped to or from anyPolicy
    @Test
    func `Mapping to or from anyPolicy is reported non-conformant`() throws {
        let anyPolicy = RFC_5280.PolicyInformation.ID.anyPolicy
        let fromAny = RFC_5280.PolicyMappings.Mapping(
            issuerDomainPolicy: anyPolicy,
            subjectDomainPolicy: subjectPolicy
        )
        let toAny = RFC_5280.PolicyMappings.Mapping(
            issuerDomainPolicy: issuerPolicy,
            subjectDomainPolicy: anyPolicy
        )
        #expect(!fromAny.isRFC5280Conformant)
        #expect(!toAny.isRFC5280Conformant)
        #expect(!RFC_5280.PolicyMappings([fromAny]).isRFC5280Conformant)

        let conformant = RFC_5280.PolicyMappings.Mapping(
            issuerDomainPolicy: issuerPolicy,
            subjectDomainPolicy: subjectPolicy
        )
        #expect(conformant.isRFC5280Conformant)
        #expect(RFC_5280.PolicyMappings([conformant]).isRFC5280Conformant)

        // Wire fidelity: a non-conformant mapping still round-trips.
        #expect(try roundTrips(RFC_5280.PolicyMappings([fromAny])))
    }

    // SkipCerts ::= INTEGER (0..MAX)
    @Test
    func `A negative InhibitAnyPolicy is rejected`() {
        #expect(throws: ISO_8824.Error.self) {
            _ = try derBytes(of: RFC_5280.InhibitAnyPolicy(skipCerts: -1))
        }
        #expect(throws: ISO_8824.Error.self) {
            _ = try RFC_5280.InhibitAnyPolicy(derEncoded: [0x02, 0x01, 0xFF])
        }
    }
}
