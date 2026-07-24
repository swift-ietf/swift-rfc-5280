// RFC_5280.CRLDistributionPoints Tests.swift

import ISO_8824
import ISO_8825
import Testing

@testable import RFC_5280

extension RFC_5280.CRLDistributionPoints {
    @Suite
    struct Test {
        @Suite struct Unit {}
        @Suite struct `Edge Case` {}
    }
}

// MARK: - Unit Tests

extension RFC_5280.CRLDistributionPoints.Test.Unit {

    // RFC 5280 §4.2.1.13 / Appendix A.1: `distributionPoint [0]` tags a
    // CHOICE so it is EXPLICIT, while `fullName [0]` inside it tags a
    // SEQUENCE OF and is IMPLICIT — the doubled a0 in the fixture is that
    // law, and is exactly what a naive implicit-only encoder gets wrong.
    @Test
    func `A fullName URI distribution point encodes explicit-then-implicit`() throws {
        let points = RFC_5280.CRLDistributionPoints([
            RFC_5280.DistributionPoint(
                distributionPoint: .fullName([
                    .uniformResourceIdentifier(try ISO_8824.IA5String("http://a.com/c"))
                ])
            )
        ])
        let fixture: [UInt8] = [
            0x30, 0x16,
            0x30, 0x14,
            0xa0, 0x12,
            0xa0, 0x10,
            0x86, 0x0e,
            0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x63,
        ]
        #expect(try derBytes(of: points) == fixture)
        #expect(try RFC_5280.CRLDistributionPoints(derEncoded: fixture) == points)
    }

    @Test
    func `A nameRelativeToCRLIssuer distribution point round-trips`() throws {
        let rdn = RFC_5280.RelativeDistinguishedName([
            RFC_5280.AttributeTypeAndValue(
                type: ISO_8824.ObjectIdentifier.NameAttributes.commonName,
                value: try ISO_8825.`Any`(erasing: try ISO_8824.PrintableString("CRL1"))
            )
        ])
        let points = RFC_5280.CRLDistributionPoints([
            RFC_5280.DistributionPoint(distributionPoint: .nameRelativeToCRLIssuer(rdn))
        ])
        #expect(try roundTrips(points))
    }

    @Test
    func `Reasons and cRLIssuer round-trip alongside the distribution point`() throws {
        var reasons = RFC_5280.ReasonFlags()
        reasons.keyCompromise = true
        reasons.cACompromise = true

        let points = RFC_5280.CRLDistributionPoints([
            RFC_5280.DistributionPoint(
                distributionPoint: .fullName([
                    .uniformResourceIdentifier(try ISO_8824.IA5String("http://example.com/crl"))
                ]),
                reasons: reasons,
                cRLIssuer: [.dNSName(try ISO_8824.IA5String("crl.example.com"))]
            )
        ])
        #expect(try roundTrips(points))

        let reparsed = try RFC_5280.CRLDistributionPoints(derEncoded: try derBytes(of: points))
        let reparsedReasons = try #require(reparsed.distributionPoints.first?.reasons)
        #expect(reparsedReasons.keyCompromise)
        #expect(reparsedReasons.cACompromise)
        #expect(!reparsedReasons.superseded)
    }

    // §4.2.1.13 criticality: SHOULD be non-critical
    @Test
    func `The extension bridge defaults to non-critical`() throws {
        let points = RFC_5280.CRLDistributionPoints([
            RFC_5280.DistributionPoint(
                distributionPoint: .fullName([
                    .uniformResourceIdentifier(try ISO_8824.IA5String("http://example.com/crl"))
                ])
            )
        ])
        let certificateExtension = try points.makeExtension()
        #expect(!certificateExtension.critical)
        #expect(certificateExtension.extnID == [2, 5, 29, 31])
        #expect(try RFC_5280.CRLDistributionPoints(certificateExtension) == points)
    }

    // §4.2.1.15: FreshestCRL shares the syntax but has its own identifier
    @Test
    func `FreshestCRL shares the syntax under its own identifier`() throws {
        let freshest = RFC_5280.FreshestCRL([
            RFC_5280.DistributionPoint(
                distributionPoint: .fullName([
                    .uniformResourceIdentifier(try ISO_8824.IA5String("http://example.com/delta"))
                ])
            )
        ])
        #expect(try roundTrips(freshest))
        let certificateExtension = try freshest.makeExtension()
        #expect(!certificateExtension.critical)
        #expect(certificateExtension.extnID == [2, 5, 29, 46])
        #expect(try RFC_5280.FreshestCRL(certificateExtension) == freshest)
    }
}

// MARK: - Edge Case Tests

extension RFC_5280.CRLDistributionPoints.Test.`Edge Case` {

    // §4.2.1.13: SEQUENCE SIZE (1..MAX)
    @Test
    func `An empty distribution point sequence is rejected`() {
        #expect(throws: ISO_8824.Error.self) {
            _ = try RFC_5280.CRLDistributionPoints(derEncoded: [0x30, 0x00])
        }
        #expect(throws: ISO_8824.Error.self) {
            _ = try derBytes(of: RFC_5280.CRLDistributionPoints([]))
        }
    }

    // §4.2.1.13: a DistributionPoint must not consist of only `reasons`
    @Test
    func `A reasons-only distribution point is rejected`() {
        var reasons = RFC_5280.ReasonFlags()
        reasons.superseded = true
        #expect(throws: ISO_8824.Error.self) {
            _ = try derBytes(of: RFC_5280.DistributionPoint(reasons: reasons))
        }
    }

    // ReasonFlags named bits stop at aACompromise(8)
    @Test
    func `ReasonFlags rejects bits beyond aACompromise`() {
        #expect(throws: ISO_8824.Error.self) {
            // BIT STRING with 0 padding bits and a set bit at position 9.
            _ = try RFC_5280.ReasonFlags(derEncoded: [0x03, 0x03, 0x00, 0x00, 0x40])
        }
    }

    // DER named-bit law: an all-zero ReasonFlags is an empty BIT STRING
    @Test
    func `An empty ReasonFlags encodes as an empty bit string`() throws {
        let bytes = try derBytes(of: RFC_5280.ReasonFlags())
        #expect(bytes == [0x03, 0x01, 0x00])
    }

    @Test
    func `A distribution point name must carry a context tag`() {
        #expect(throws: ISO_8824.Error.self) {
            // A bare SEQUENCE is not a DistributionPointName.
            _ = try RFC_5280.DistributionPoint.Name(derEncoded: [0x30, 0x00])
        }
    }

    // §4.2.1.13: conforming CAs SHOULD NOT use nameRelativeToCRLIssuer, and
    // cRLIssuer MUST contain only the CRL issuer's directory name. Both are
    // preserved for wire fidelity and reported, so a fail-closed policy
    // layer can reject them.
    @Test
    func `Profile deviations are preserved and reportable`() throws {
        let directoryName = RFC_5280.GeneralName.directoryName(
            RFC_5280.Name([
                RFC_5280.RelativeDistinguishedName([
                    RFC_5280.AttributeTypeAndValue(
                        type: ISO_8824.ObjectIdentifier.NameAttributes.commonName,
                        value: try ISO_8825.`Any`(erasing: try ISO_8824.PrintableString("Issuer"))
                    )
                ])
            ])
        )
        let uri = RFC_5280.GeneralName.uniformResourceIdentifier(
            try ISO_8824.IA5String("http://example.com/crl")
        )

        let conformant = RFC_5280.DistributionPoint(
            distributionPoint: .fullName([uri]),
            cRLIssuer: [directoryName]
        )
        #expect(conformant.isRFC5280Conformant)
        #expect(RFC_5280.CRLDistributionPoints([conformant]).isRFC5280Conformant)
        #expect(RFC_5280.FreshestCRL([conformant]).isRFC5280Conformant)

        // The discouraged relative-name form.
        let relative = RFC_5280.DistributionPoint(
            distributionPoint: .nameRelativeToCRLIssuer(
                RFC_5280.RelativeDistinguishedName([
                    RFC_5280.AttributeTypeAndValue(
                        type: ISO_8824.ObjectIdentifier.NameAttributes.commonName,
                        value: try ISO_8825.`Any`(erasing: try ISO_8824.PrintableString("CRL1"))
                    )
                ])
            )
        )
        #expect(!relative.isRFC5280Conformant)
        #expect(!RFC_5280.CRLDistributionPoints([relative]).isRFC5280Conformant)
        #expect(try roundTrips(RFC_5280.CRLDistributionPoints([relative])))

        // A cRLIssuer that is not a directory name.
        let badIssuer = RFC_5280.DistributionPoint(
            distributionPoint: .fullName([uri]),
            cRLIssuer: [uri]
        )
        #expect(!badIssuer.isRFC5280Conformant)
        #expect(try roundTrips(RFC_5280.CRLDistributionPoints([badIssuer])))
    }
}
