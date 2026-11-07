// RFC_5280.CertificateList Tests.swift

import ISO_8824
import ISO_8825
import Testing

@testable import RFC_5280

enum `RFC_5280.CertificateList Tests` {}

extension `RFC_5280.CertificateList Tests` {
    @Suite
    struct Test {
        @Suite struct Unit {}
        @Suite struct `Edge Case` {}
        @Suite struct Integration {}
    }
}

// MARK: - Fixtures

private let ecdsaWithSHA256 = RFC_5280.AlgorithmIdentifier(algorithm: [1, 2, 840, 10045, 4, 3, 2])

private func issuerName() throws(ISO_8824.Error) -> RFC_5280.Name {
    RFC_5280.Name([
        RFC_5280.RelativeDistinguishedName([
            RFC_5280.AttributeTypeAndValue(
                type: ISO_8824.ObjectIdentifier.NameAttributes.commonName,
                value: try ISO_8825.`Any`(erasing: ISO_8824.PrintableString("Test CA"))
            )
        ])
    ])
}

private func thisUpdate() throws(ISO_8824.Error) -> RFC_5280.Time {
    try RFC_5280.Time(year: 2026, month: 7, day: 24, hours: 0, minutes: 0, seconds: 0)
}

private func nextUpdate() throws(ISO_8824.Error) -> RFC_5280.Time {
    try RFC_5280.Time(year: 2026, month: 8, day: 24, hours: 0, minutes: 0, seconds: 0)
}

// MARK: - Unit Tests

extension `RFC_5280.CertificateList Tests`.Test.Unit {

    // RFC 5280 §5.1.2.1: a v1 CRL omits the version field entirely
    @Test
    func `A v1 CRL with no revocations round-trips`() throws {
        let list = RFC_5280.TBSCertList(
            signature: ecdsaWithSHA256,
            issuer: try issuerName(),
            thisUpdate: try thisUpdate(),
            nextUpdate: try nextUpdate()
        )
        #expect(list.version == nil)
        #expect(list.minimumRequiredVersion == nil)
        #expect(list.isRFC5280Conformant)
        #expect(try roundTrips(list))
    }

    @Test
    func `Revoked entries round-trip`() throws {
        let list = RFC_5280.TBSCertList(
            signature: ecdsaWithSHA256,
            issuer: try issuerName(),
            thisUpdate: try thisUpdate(),
            revokedCertificates: [
                RFC_5280.TBSCertList.RevokedCertificate(
                    userCertificate: RFC_5280.Certificate.SerialNumber(UInt64(0x1234)),
                    revocationDate: try thisUpdate()
                )
            ]
        )
        #expect(try roundTrips(list))
        let reparsed = try RFC_5280.TBSCertList(derEncoded: try derBytes(of: list))
        #expect(reparsed.revokedCertificates.count == 1)
        #expect(reparsed.nextUpdate == nil)
    }

    // §5.1.2.1: entry extensions force v2
    @Test
    func `Entry extensions require v2`() throws {
        let entry = RFC_5280.TBSCertList.RevokedCertificate(
            userCertificate: RFC_5280.Certificate.SerialNumber(UInt64(7)),
            revocationDate: try thisUpdate(),
            crlEntryExtensions: [try RFC_5280.CRLReason.keyCompromise.makeExtension()]
        )
        let list = RFC_5280.TBSCertList(
            version: .v2,
            signature: ecdsaWithSHA256,
            issuer: try issuerName(),
            thisUpdate: try thisUpdate(),
            revokedCertificates: [entry]
        )
        #expect(list.minimumRequiredVersion == .v2)
        #expect(list.isRFC5280Conformant)
        #expect(try roundTrips(list))
    }

    // §5.1.2.1: CRL extensions force v2
    @Test
    func `CRL extensions require v2`() throws {
        let list = RFC_5280.TBSCertList(
            version: .v2,
            signature: ecdsaWithSHA256,
            issuer: try issuerName(),
            thisUpdate: try thisUpdate(),
            crlExtensions: [try RFC_5280.CRLNumber(UInt64(3)).makeExtension()]
        )
        #expect(list.minimumRequiredVersion == .v2)
        #expect(list.isRFC5280Conformant)
        #expect(try roundTrips(list))
    }

    // §5.3.1: CRLReason is an ENUMERATED, not an INTEGER
    @Test
    func `CRLReason encodes as an ENUMERATED`() throws {
        // ENUMERATED (0x0a) with value keyCompromise(1).
        let fixture: [UInt8] = [0x0a, 0x01, 0x01]
        #expect(try derBytes(of: RFC_5280.CRLReason.keyCompromise) == fixture)
        #expect(try RFC_5280.CRLReason(derEncoded: fixture) == .keyCompromise)
        #expect(RFC_5280.CRLReason.keyCompromise.description == "keyCompromise")
    }
}

// MARK: - Edge Case Tests

extension `RFC_5280.CertificateList Tests`.Test.`Edge Case` {

    // §5.3.1: value 7 is unassigned; unknown codes are preserved, not rejected
    @Test
    func `Unassigned reason codes are preserved and reported`() throws {
        let unassigned = RFC_5280.CRLReason(rawValue: 7)
        #expect(!unassigned.isRFC5280Assigned)
        #expect(!unassigned.isRFC5280Conformant)
        #expect(unassigned.description == "CRLReason(rawValue: 7)")
        #expect(try roundTrips(unassigned))

        // unspecified(0) is assigned but MUST NOT be used.
        #expect(RFC_5280.CRLReason.unspecified.isRFC5280Assigned)
        #expect(!RFC_5280.CRLReason.unspecified.isRFC5280Conformant)
        #expect(RFC_5280.CRLReason.removeFromCRL.isRFC5280Conformant)
    }

    // §5.1.2.1: CRLs stop at v2 — v3 is a certificate-only version
    @Test
    func `A v3 CRL version is reported non-conformant`() throws {
        let list = RFC_5280.TBSCertList(
            version: .v3,
            signature: ecdsaWithSHA256,
            issuer: try issuerName(),
            thisUpdate: try thisUpdate()
        )
        #expect(!list.isRFC5280Conformant)
        // Wire fidelity: it still round-trips.
        #expect(try roundTrips(list))
    }

    // §5.1.2.1: the version field MUST be absent for a v1 CRL
    @Test
    func `A version present without extensions is non-conformant`() throws {
        let list = RFC_5280.TBSCertList(
            version: .v2,
            signature: ecdsaWithSHA256,
            issuer: try issuerName(),
            thisUpdate: try thisUpdate()
        )
        #expect(list.minimumRequiredVersion == nil)
        #expect(!list.isRFC5280Conformant)
    }

    // RFC 5280 §5.2.5 / X.690: `[n] IMPLICIT BOOLEAN DEFAULT FALSE`. The
    // implicit context tag REPLACES BOOLEAN's own 0x01 identifier with
    // 0x81, which is exactly why decoding needs `decodeDefault`'s builder
    // form — the builderless overload decodes against BOOLEAN's identifier
    // and rejects the context tag. DER also requires a DEFAULT sitting at
    // its default value to be omitted entirely rather than encoded.
    //
    // This is the DEFAULT-under-implicit-tag half of the tagging class whose
    // other half is pinned by the doubled-a0 fixture in
    // `RFC_5280.CRLDistributionPoints Tests`.
    @Test
    func `An implicitly tagged BOOLEAN DEFAULT encodes to the known bytes`() throws {
        // onlyContainsUserCerts [1] TRUE: 0x81 is the context tag, not 0x01.
        let userCertsOnly = RFC_5280.IssuingDistributionPoint(onlyContainsUserCerts: true)
        let userCertsFixture: [UInt8] = [0x30, 0x03, 0x81, 0x01, 0xff]
        #expect(try derBytes(of: userCertsOnly) == userCertsFixture)
        #expect(try RFC_5280.IssuingDistributionPoint(derEncoded: userCertsFixture) == userCertsOnly)

        // The same shape at a different tag number: indirectCRL [4].
        let indirect = RFC_5280.IssuingDistributionPoint(indirectCRL: true)
        let indirectFixture: [UInt8] = [0x30, 0x03, 0x84, 0x01, 0xff]
        #expect(try derBytes(of: indirect) == indirectFixture)
        #expect(try RFC_5280.IssuingDistributionPoint(derEncoded: indirectFixture) == indirect)

        // Every field at its default omits, leaving an empty SEQUENCE.
        let allDefault = RFC_5280.IssuingDistributionPoint()
        #expect(try derBytes(of: allDefault) == [0x30, 0x00])
        #expect(try RFC_5280.IssuingDistributionPoint(derEncoded: [0x30, 0x00]) == allDefault)

        // DER forbids encoding a DEFAULT at its default value: an explicit
        // FALSE for onlyContainsUserCerts must be rejected, not accepted.
        #expect(throws: ISO_8824.Error.self) {
            _ = try RFC_5280.IssuingDistributionPoint(derEncoded: [0x30, 0x03, 0x81, 0x01, 0x00])
        }
    }

    // §5.2.5: at most one of the three scope flags may be TRUE
    @Test
    func `Conflicting issuing distribution point scopes are reported`() throws {
        let conflicting = RFC_5280.IssuingDistributionPoint(
            onlyContainsUserCerts: true,
            onlyContainsCACerts: true
        )
        #expect(!conflicting.isRFC5280Conformant)
        #expect(try roundTrips(conflicting))

        let scoped = RFC_5280.IssuingDistributionPoint(onlyContainsUserCerts: true)
        #expect(scoped.isRFC5280Conformant)
        #expect(try roundTrips(scoped))

        // §5.2.5 criticality: MUST be critical
        #expect(try scoped.makeExtension().critical)
    }

    // §5.3.3: the entry issuer is a directory name
    @Test
    func `A non-directory certificate issuer is reported`() throws {
        let conformant = RFC_5280.CertificateIssuer([
            .directoryName(try issuerName())
        ])
        #expect(conformant.isRFC5280Conformant)
        #expect(try conformant.makeExtension().critical)

        let nonConformant = RFC_5280.CertificateIssuer([
            .dNSName(ISO_8824.IA5String("ca.example.com"))
        ])
        #expect(!nonConformant.isRFC5280Conformant)
        #expect(try roundTrips(nonConformant))
    }
}

// MARK: - Integration Tests

extension `RFC_5280.CertificateList Tests`.Test.Integration {

    // A complete signed v2 CRL exercising §5.1, §5.2 and §5.3 together
    @Test
    func `A fully populated v2 CRL round-trips`() throws {
        let entry = RFC_5280.TBSCertList.RevokedCertificate(
            userCertificate: RFC_5280.Certificate.SerialNumber(UInt64(0xDEAD)),
            revocationDate: try thisUpdate(),
            crlEntryExtensions: [
                try RFC_5280.CRLReason.cessationOfOperation.makeExtension(),
                try RFC_5280.InvalidityDate(
                    date: try ISO_8824.GeneralizedTime(
                        year: 2026,
                        month: 7,
                        day: 20,
                        hours: 12,
                        minutes: 0,
                        seconds: 0,
                        fractionalSeconds: 0
                    )
                ).makeExtension(),
                try RFC_5280.CertificateIssuer([.directoryName(try issuerName())]).makeExtension(),
            ]
        )

        let tbsCertList = RFC_5280.TBSCertList(
            version: .v2,
            signature: ecdsaWithSHA256,
            issuer: try issuerName(),
            thisUpdate: try thisUpdate(),
            nextUpdate: try nextUpdate(),
            revokedCertificates: [entry],
            crlExtensions: [
                try RFC_5280.CRLNumber(UInt64(42)).makeExtension(),
                try RFC_5280.IssuingDistributionPoint(
                    distributionPoint: .fullName([
                        .uniformResourceIdentifier(ISO_8824.IA5String("http://example.com/crl"))
                    ]),
                    onlyContainsUserCerts: true
                ).makeExtension(),
            ]
        )

        let list = RFC_5280.CertificateList(
            tbsCertList: tbsCertList,
            signatureAlgorithm: ecdsaWithSHA256,
            signatureValue: try ISO_8824.BitString(bytes: [0x01, 0x02, 0x03, 0x04], paddingBits: 0)
        )

        #expect(try roundTrips(list))
        #expect(list.hasConsistentSignatureAlgorithm)
        #expect(list.tbsCertList.isRFC5280Conformant)

        // The typed views decode back out of the reparsed generic extensions.
        let reparsed = try RFC_5280.CertificateList(derEncoded: try derBytes(of: list))
        let crlExtensions = Dictionary(
            uniqueKeysWithValues: reparsed.tbsCertList.crlExtensions.map { ($0.extnID, $0) }
        )
        let number = try RFC_5280.CRLNumber(try #require(crlExtensions[RFC_5280.Extension.ID.cRLNumber]))
        #expect(number == RFC_5280.CRLNumber(UInt64(42)))

        let entryExtensions = Dictionary(
            uniqueKeysWithValues: try #require(reparsed.tbsCertList.revokedCertificates.first)
                .crlEntryExtensions.map { ($0.extnID, $0) }
        )
        let reason = try RFC_5280.CRLReason(try #require(entryExtensions[RFC_5280.Extension.ID.reasonCode]))
        #expect(reason == .cessationOfOperation)
    }

    // §5.1.1.2: signatureAlgorithm MUST equal tbsCertList.signature
    @Test
    func `A signature algorithm mismatch is preserved and reported`() throws {
        let list = RFC_5280.CertificateList(
            tbsCertList: RFC_5280.TBSCertList(
                signature: ecdsaWithSHA256,
                issuer: try issuerName(),
                thisUpdate: try thisUpdate()
            ),
            signatureAlgorithm: RFC_5280.AlgorithmIdentifier(algorithm: [1, 2, 840, 10045, 4, 3, 3]),
            signatureValue: try ISO_8824.BitString(bytes: [0x00], paddingBits: 0)
        )
        #expect(!list.hasConsistentSignatureAlgorithm)
        #expect(try roundTrips(list))
    }
}
