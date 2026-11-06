// RFC_5280.TBSCertificate Tests.swift

import ISO_8824
import ISO_8825
import Testing

@testable import RFC_5280

enum `RFC_5280.TBSCertificate Tests` {}

extension `RFC_5280.TBSCertificate Tests` {
    @Suite
    struct Test {
        @Suite struct Unit {}
        @Suite struct Integration {}
    }
}

// MARK: - Fixtures

private func makeName(commonName: String) throws(ISO_8824.Error) -> RFC_5280.Name {
    RFC_5280.Name([
        RFC_5280.RelativeDistinguishedName([
            RFC_5280.AttributeTypeAndValue(
                type: ISO_8824.ObjectIdentifier.NameAttributes.commonName,
                value: try ISO_8825.`Any`(erasing: try ISO_8824.PrintableString(commonName))
            )
        ])
    ])
}

private func makeSubjectPublicKeyInfo() throws(ISO_8824.Error) -> RFC_5280.SubjectPublicKeyInfo {
    RFC_5280.SubjectPublicKeyInfo(
        algorithm: RFC_5280.AlgorithmIdentifier(
            algorithm: [1, 2, 840, 10045, 2, 1],
            parameters: try ISO_8825.`Any`(erasing: [1, 2, 840, 10045, 3, 1, 7] as ISO_8824.ObjectIdentifier)
        ),
        subjectPublicKey: try ISO_8824.BitString(bytes: [0x04, 0x01, 0x02, 0x03], paddingBits: 0)
    )
}

private func makeValidity() throws(ISO_8824.Error) -> RFC_5280.Validity {
    RFC_5280.Validity(
        notBefore: try RFC_5280.Time(year: 2026, month: 7, day: 23, hours: 0, minutes: 0, seconds: 0),
        notAfter: try RFC_5280.Time(year: 2027, month: 7, day: 23, hours: 0, minutes: 0, seconds: 0)
    )
}

private let ecdsaWithSHA256 = RFC_5280.AlgorithmIdentifier(algorithm: [1, 2, 840, 10045, 4, 3, 2])

// The DER prefix of an explicitly tagged version field: [0] { INTEGER v }
private func versionField(_ value: UInt8) -> [UInt8] {
    [0xa0, 0x03, 0x02, 0x01, value]
}

private func contains(_ haystack: [UInt8], _ needle: [UInt8]) -> Bool {
    guard haystack.count >= needle.count else { return false }
    return (0...(haystack.count - needle.count)).contains { start in
        Array(haystack[start..<(start + needle.count)]) == needle
    }
}

// MARK: - Unit Tests

extension `RFC_5280.TBSCertificate Tests`.Test.Unit {

    // RFC 5280 §4.1.2.1: DEFAULT v1 must be omitted from the DER encoding
    @Test
    func `A v1 certificate omits the version field`() throws {
        let tbs = RFC_5280.TBSCertificate(
            version: .v1,
            serialNumber: RFC_5280.Certificate.SerialNumber(UInt64(1)),
            signature: ecdsaWithSHA256,
            issuer: try makeName(commonName: "Test CA"),
            validity: try makeValidity(),
            subject: try makeName(commonName: "Test Subject"),
            subjectPublicKeyInfo: try makeSubjectPublicKeyInfo()
        )
        let bytes = try derBytes(of: tbs)
        #expect(!contains(bytes, versionField(0)))
        #expect(try RFC_5280.TBSCertificate(derEncoded: bytes) == tbs)
    }

    @Test
    func `A v3 certificate encodes the explicitly tagged version`() throws {
        let tbs = RFC_5280.TBSCertificate(
            version: .v3,
            serialNumber: RFC_5280.Certificate.SerialNumber(UInt64(2)),
            signature: ecdsaWithSHA256,
            issuer: try makeName(commonName: "Test CA"),
            validity: try makeValidity(),
            subject: try makeName(commonName: "Test Subject"),
            subjectPublicKeyInfo: try makeSubjectPublicKeyInfo(),
            extensions: [
                try RFC_5280.BasicConstraints(isCA: false).makeExtension(critical: false)
            ]
        )
        let bytes = try derBytes(of: tbs)
        #expect(contains(bytes, versionField(2)))
        #expect(try RFC_5280.TBSCertificate(derEncoded: bytes) == tbs)
    }

    // RFC 5280 §4.1.2.1: version floor follows the populated fields
    @Test
    func `minimumRequiredVersion follows the populated fields`() throws {
        var tbs = RFC_5280.TBSCertificate(
            version: .v1,
            serialNumber: RFC_5280.Certificate.SerialNumber(UInt64(3)),
            signature: ecdsaWithSHA256,
            issuer: try makeName(commonName: "Test CA"),
            validity: try makeValidity(),
            subject: try makeName(commonName: "Test Subject"),
            subjectPublicKeyInfo: try makeSubjectPublicKeyInfo()
        )
        #expect(tbs.minimumRequiredVersion == .v1)

        tbs.subjectUniqueID = try ISO_8824.BitString(bytes: [0xff], paddingBits: 0)
        #expect(tbs.minimumRequiredVersion == .v2)

        tbs.extensions = [try RFC_5280.BasicConstraints(isCA: true).makeExtension()]
        #expect(tbs.minimumRequiredVersion == .v3)

        #expect(RFC_5280.Certificate.Version.v1 < .v2)
        #expect(RFC_5280.Certificate.Version.v2 < .v3)
    }
}

// MARK: - Integration Tests

extension `RFC_5280.TBSCertificate Tests`.Test.Integration {

    // A CA-profile certificate exercising every typed extension in one structure
    @Test
    func `A fully populated v3 CA certificate round-trips`() throws {
        var keyUsage = RFC_5280.KeyUsage()
        keyUsage.keyCertSign = true
        keyUsage.cRLSign = true

        let tbs = RFC_5280.TBSCertificate(
            version: .v3,
            serialNumber: RFC_5280.Certificate.SerialNumber(UInt64(0x0123_4567)),
            signature: ecdsaWithSHA256,
            issuer: try makeName(commonName: "Test Root CA"),
            validity: try makeValidity(),
            subject: try makeName(commonName: "Test Intermediate CA"),
            subjectPublicKeyInfo: try makeSubjectPublicKeyInfo(),
            issuerUniqueID: try ISO_8824.BitString(bytes: [0x0f], paddingBits: 0),
            subjectUniqueID: try ISO_8824.BitString(bytes: [0xf0], paddingBits: 0),
            extensions: [
                try RFC_5280.BasicConstraints(isCA: true, pathLenConstraint: 0).makeExtension(),
                try keyUsage.makeExtension(),
                try RFC_5280.SubjectKeyIdentifier(
                    keyIdentifier: ISO_8824.OctetString(contentBytes: [0x01, 0x02, 0x03, 0x04])
                ).makeExtension(),
                try RFC_5280.AuthorityKeyIdentifier(
                    keyIdentifier: ISO_8824.OctetString(contentBytes: [0x05, 0x06, 0x07, 0x08])
                ).makeExtension(),
                try RFC_5280.SubjectAlternativeName([
                    .dNSName(try ISO_8824.IA5String("ca.example.com"))
                ]).makeExtension(),
                try RFC_5280.NameConstraints(
                    permittedSubtrees: [
                        RFC_5280.GeneralSubtree(base: .dNSName(try ISO_8824.IA5String("example.com")))
                    ]
                ).makeExtension(),
                try RFC_5280.ExtendedKeyUsage([
                    RFC_5280.ExtendedKeyUsage.ID.serverAuth
                ]).makeExtension(),
                try RFC_5280.AuthorityInformationAccess([
                    RFC_5280.AccessDescription(
                        accessMethod: RFC_5280.AccessDescription.ID.ocsp,
                        accessLocation: .uniformResourceIdentifier(try ISO_8824.IA5String("http://ocsp.example.com"))
                    )
                ]).makeExtension(),
            ]
        )

        let bytes = try derBytes(of: tbs)
        let reparsed = try RFC_5280.TBSCertificate(derEncoded: bytes)
        #expect(reparsed == tbs)
        #expect(try derBytes(of: reparsed) == bytes)

        // The typed views decode back out of the reparsed generic extensions.
        let extensionsByID = Dictionary(
            uniqueKeysWithValues: reparsed.extensions.map { ($0.extnID, $0) }
        )
        let basicConstraints = try RFC_5280.BasicConstraints(
            try #require(extensionsByID[RFC_5280.Extension.ID.basicConstraints])
        )
        #expect(basicConstraints.isCA)
        #expect(basicConstraints.pathLenConstraint == 0)

        let reparsedKeyUsage = try RFC_5280.KeyUsage(
            try #require(extensionsByID[RFC_5280.Extension.ID.keyUsage])
        )
        #expect(reparsedKeyUsage == keyUsage)

        let san = try RFC_5280.SubjectAlternativeName(
            try #require(extensionsByID[RFC_5280.Extension.ID.subjectAlternativeName])
        )
        #expect(san.names == [.dNSName(try ISO_8824.IA5String("ca.example.com"))])
    }
}
