// RFC_5280.CertificatePolicies Tests.swift

import ISO_8824
import ISO_8825
import Testing

@testable import RFC_5280

enum `IETF.RFC.5280.CertificatePolicies Tests` {}

extension `IETF.RFC.5280.CertificatePolicies Tests` {
    @Suite
    struct Test {
        @Suite struct Unit {}
        @Suite struct `Edge Case` {}
    }
}

// A policy OID from the example arc used throughout RFC 5280's own text.
private let examplePolicy: ISO.`8824`.ObjectIdentifier = [2, 16, 840, 1, 101, 3, 2, 1, 48, 1]
private let otherPolicy: ISO.`8824`.ObjectIdentifier = [2, 16, 840, 1, 101, 3, 2, 1, 48, 2]

// MARK: - Unit Tests

extension `IETF.RFC.5280.CertificatePolicies Tests`.Test.Unit {

    // RFC 5280 §4.2.1.4: the common case is an OID with no qualifiers
    @Test
    func `A bare policy OID round-trips`() throws {
        let policies = IETF.RFC.`5280`.CertificatePolicies([
            IETF.RFC.`5280`.PolicyInformation(policyIdentifier: examplePolicy)
        ])
        #expect(try roundTrips(policies))
    }

    @Test
    func `A CPS qualifier round-trips`() throws {
        let policies = IETF.RFC.`5280`.CertificatePolicies([
            IETF.RFC.`5280`.PolicyInformation(
                policyIdentifier: examplePolicy,
                policyQualifiers: [
                    IETF.RFC.`5280`.PolicyQualifierInfo(
                        policyQualifierID: IETF.RFC.`5280`.PolicyQualifierInfo.ID.cps,
                        qualifier: try ISO.`8825`.`Any`(erasing: ISO.`8824`.IA5String("https://example.com/cps"))
                    )
                ]
            )
        ])
        #expect(try roundTrips(policies))

        let qualifier = try #require(policies.policies.first?.policyQualifiers?.first)
        #expect(qualifier.isRFC5280Conformant)
        #expect(try qualifier.cpsURI() == (try ISO.`8824`.IA5String("https://example.com/cps")))
    }

    @Test
    func `A user-notice qualifier round-trips`() throws {
        let notice = IETF.RFC.`5280`.UserNotice(explicitText: .utf8String(ISO.`8824`.UTF8String("Example notice")))
        let policies = IETF.RFC.`5280`.CertificatePolicies([
            IETF.RFC.`5280`.PolicyInformation(
                policyIdentifier: examplePolicy,
                policyQualifiers: [
                    IETF.RFC.`5280`.PolicyQualifierInfo(
                        policyQualifierID: IETF.RFC.`5280`.PolicyQualifierInfo.ID.unotice,
                        qualifier: try ISO.`8825`.`Any`(erasing: notice)
                    )
                ]
            )
        ])
        #expect(try roundTrips(policies))

        let qualifier = try #require(policies.policies.first?.policyQualifiers?.first)
        #expect(try qualifier.userNotice() == notice)
    }

    // RFC 5280 §4.2.1.4: anyPolicy is { id-ce-certificatePolicies 0 }
    @Test
    func `anyPolicy is recognised`() {
        #expect(IETF.RFC.`5280`.PolicyInformation.ID.anyPolicy == [2, 5, 29, 32, 0])
        let policies = IETF.RFC.`5280`.CertificatePolicies([
            IETF.RFC.`5280`.PolicyInformation(policyIdentifier: IETF.RFC.`5280`.PolicyInformation.ID.anyPolicy)
        ])
        #expect(policies.assertsAnyPolicy)
        #expect(
            !IETF.RFC.`5280`.CertificatePolicies([
                IETF.RFC.`5280`.PolicyInformation(policyIdentifier: examplePolicy)
            ]).assertsAnyPolicy
        )
    }

    // §4.2.1.4 criticality: SHOULD be non-critical
    @Test
    func `The extension bridge defaults to non-critical`() throws {
        let policies = IETF.RFC.`5280`.CertificatePolicies([
            IETF.RFC.`5280`.PolicyInformation(policyIdentifier: examplePolicy)
        ])
        let certificateExtension = try policies.makeExtension()
        #expect(!certificateExtension.critical)
        #expect(certificateExtension.extnID == IETF.RFC.`5280`.Extension.ID.certificatePolicies)
        #expect(certificateExtension.extnID == [2, 5, 29, 32])
        #expect(try IETF.RFC.`5280`.CertificatePolicies(certificateExtension) == policies)
    }
}

// MARK: - Edge Case Tests

extension `IETF.RFC.5280.CertificatePolicies Tests`.Test.`Edge Case` {

    // §4.2.1.4: SEQUENCE SIZE (1..MAX)
    @Test
    func `An empty policy sequence is rejected`() {
        #expect(throws: ISO.`8824`.Error.self) {
            _ = try IETF.RFC.`5280`.CertificatePolicies(derEncoded: [0x30, 0x00])
        }
        #expect(throws: ISO.`8824`.Error.self) {
            _ = try derBytes(of: IETF.RFC.`5280`.CertificatePolicies([]))
        }
    }

    // §4.2.1.4: policyQualifiers is SEQUENCE SIZE (1..MAX) when present
    @Test
    func `An empty qualifier sequence is rejected on serialize`() {
        let policies = IETF.RFC.`5280`.CertificatePolicies([
            IETF.RFC.`5280`.PolicyInformation(policyIdentifier: examplePolicy, policyQualifiers: [])
        ])
        #expect(throws: ISO.`8824`.Error.self) {
            _ = try derBytes(of: policies)
        }
    }

    // §4.2.1.4: a policy OID must not appear twice
    @Test
    func `Duplicate policy OIDs are reported`() {
        let duplicated = IETF.RFC.`5280`.CertificatePolicies([
            IETF.RFC.`5280`.PolicyInformation(policyIdentifier: examplePolicy),
            IETF.RFC.`5280`.PolicyInformation(policyIdentifier: examplePolicy),
        ])
        #expect(duplicated.hasDuplicatePolicies)

        let distinct = IETF.RFC.`5280`.CertificatePolicies([
            IETF.RFC.`5280`.PolicyInformation(policyIdentifier: examplePolicy),
            IETF.RFC.`5280`.PolicyInformation(policyIdentifier: otherPolicy),
        ])
        #expect(!distinct.hasDuplicatePolicies)
    }

    // Every preserved profile violation must be reachable through a
    // predicate, so a fail-closed policy layer can reject it.
    @Test
    func `The aggregate predicate folds duplicates and qualifier types`() throws {
        let conformant = IETF.RFC.`5280`.CertificatePolicies([
            IETF.RFC.`5280`.PolicyInformation(policyIdentifier: examplePolicy)
        ])
        #expect(conformant.isRFC5280Conformant)

        let duplicated = IETF.RFC.`5280`.CertificatePolicies([
            IETF.RFC.`5280`.PolicyInformation(policyIdentifier: examplePolicy),
            IETF.RFC.`5280`.PolicyInformation(policyIdentifier: examplePolicy),
        ])
        #expect(!duplicated.isRFC5280Conformant)

        let unknownQualifier = IETF.RFC.`5280`.CertificatePolicies([
            IETF.RFC.`5280`.PolicyInformation(
                policyIdentifier: examplePolicy,
                policyQualifiers: [
                    IETF.RFC.`5280`.PolicyQualifierInfo(
                        policyQualifierID: [1, 3, 6, 1, 4, 1, 99999, 7],
                        qualifier: try ISO.`8825`.`Any`(erasing: ISO.`8824`.UTF8String("opaque"))
                    )
                ]
            )
        ])
        #expect(!unknownQualifier.isRFC5280Conformant)
        #expect(!(try #require(unknownQualifier.policies.first).isRFC5280Conformant))
    }

    // A qualifier type outside the two the profile defines is preserved
    @Test
    func `An unknown qualifier type is preserved but flagged`() throws {
        let qualifier = IETF.RFC.`5280`.PolicyQualifierInfo(
            policyQualifierID: [1, 3, 6, 1, 4, 1, 99999, 7],
            qualifier: try ISO.`8825`.`Any`(erasing: ISO.`8824`.UTF8String("opaque"))
        )
        #expect(!qualifier.isRFC5280Conformant)
        let policies = IETF.RFC.`5280`.CertificatePolicies([
            IETF.RFC.`5280`.PolicyInformation(policyIdentifier: examplePolicy, policyQualifiers: [qualifier])
        ])
        #expect(try roundTrips(policies))
    }
}
