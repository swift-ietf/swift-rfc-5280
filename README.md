# swift-rfc-5280

![Development Status](https://img.shields.io/badge/status-active--development-blue.svg)

X.509 certificate and certificate-revocation-list structures profiled by RFC 5280.

## Standard Reference

- **RFC**: 5280
- **Title**: Internet X.509 Public Key Infrastructure Certificate and CRL Profile

## Installation

Add the package to your `Package.swift` dependencies:

```swift
dependencies: [
    .package(url: "https://github.com/swift-ietf/swift-rfc-5280.git", branch: "main")
]
```

Add the product to a target that needs it:

```swift
.target(
    name: "YourTarget",
    dependencies: [
        .product(name: "RFC 5280", package: "swift-rfc-5280")
    ]
)
```

## License

Apache 2.0. See [LICENSE.md](LICENSE.md).
