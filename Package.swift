// swift-tools-version: 6.3.3

import PackageDescription

// RFC 5280 - Internet X.509 Public Key Infrastructure
// Certificate and Certificate Revocation List (CRL) Profile
// https://www.rfc-editor.org/rfc/rfc5280
let package = Package(
    name: "swift-rfc-5280",
    platforms: [
        .macOS(.v26),
        .iOS(.v26),
        .tvOS(.v26),
        .watchOS(.v26),
        .visionOS(.v26),
    ],
    products: [
        .library(
            name: "RFC 5280",
            targets: ["RFC 5280"]
        )
    ],
    dependencies: [
        // ISO 8824 (X.680) value law and ISO 8825 (X.690) DER encoding law.
        // Published on main this session, so canonical URLs (branch: main) per
        // [PKG-DEP-009]; the mirror config resolves them to the local trees.
        .package(url: "https://github.com/swift-iso/swift-iso-8824.git", branch: "main"),
        .package(url: "https://github.com/swift-iso/swift-iso-8825.git", branch: "main"),
        // Name-constraint matching law (§4.2.1.10) delegates its name and
        // address semantics to the Institute owners. These are published, so
        // they use canonical URLs (branch: main) per [PKG-DEP-009]; the mirror
        // config resolves them to the local trees for the coordinator gate.
        .package(url: "https://github.com/swift-standards/swift-domain-standard.git", branch: "main"),
        //    The IP address owners are the RFC packages themselves; the
        //    `-standard` umbrellas over them are re-export shims, so depending
        //    on them would be an edge to a re-export rather than to the owner.
        .package(url: "https://github.com/swift-ietf/swift-rfc-791.git", branch: "main", traits: ["Coder"]),
        .package(url: "https://github.com/swift-ietf/swift-rfc-4291.git", branch: "main", traits: ["Coder"]),
        // The iPAddress matching law (§4.2.1.10) bridges ASN.1 octet content
        // (UInt8) into the byte-domain `Byte` substrate the IPv4/IPv6 address
        // parsers require ([API-BYTE-003]/[API-BYTE-008]) — a boundary surface
        // with an independent Byte-domain judgment, so the previously-deferred
        // Byte primitives dep is now taken (canonical URL per [PKG-DEP-009]).
        .package(url: "https://github.com/swift-atoms/swift-byte.git", branch: "main"),
    ],
    targets: [
        .target(
            name: "RFC 5280",
            dependencies: [
                .product(name: "ISO 8824", package: "swift-iso-8824"),
                .product(name: "ISO 8825", package: "swift-iso-8825"),
                .product(name: "Domain Standard", package: "swift-domain-standard"),
                .product(name: "RFC 791", package: "swift-rfc-791"),
                .product(name: "RFC 4291", package: "swift-rfc-4291"),
                .product(name: "Byte", package: "swift-byte"),
            ]
        ),
        .testTarget(
            name: "RFC 5280 Tests",
            dependencies: [
                "RFC 5280"
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)

extension String {
    var tests: Self { self + " Tests" }
}

for target in package.targets where ![.system, .binary, .plugin, .macro].contains(target.type) {
    let ecosystem: [SwiftSetting] = [
        .strictMemorySafety(),
        .enableUpcomingFeature("ExistentialAny"),
        .enableUpcomingFeature("InternalImportsByDefault"),
        .enableUpcomingFeature("MemberImportVisibility"),
        .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
        .enableExperimentalFeature("Lifetimes"),
        .enableExperimentalFeature("SuppressedAssociatedTypes"),
    ]

    let package: [SwiftSetting] = []

    target.swiftSettings = (target.swiftSettings ?? []) + ecosystem + package
}
