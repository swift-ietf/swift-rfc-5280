// RFC_5280.InhibitAnyPolicy.swift
// RFC 5280 §4.2.1.14 — Inhibit anyPolicy
// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.14

public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `InhibitAnyPolicy ::= SkipCerts` with `SkipCerts ::= INTEGER (0..MAX)`
    /// (RFC 5280 §4.2.1.14).
    ///
    /// Used in CA certificates to declare that the special `anyPolicy`
    /// OID is not considered an explicit match for other certificate
    /// policies; ``skipCerts`` is the number of additional certificates
    /// that may appear in the path before `anyPolicy` is no longer
    /// permitted.
    ///
    /// Criticality law: conforming CAs MUST mark this extension as critical.
    public struct InhibitAnyPolicy: Hashable, Sendable {
        /// The number of additional non-self-issued certificates that may
        /// appear before `anyPolicy` is no longer permitted.
        public var skipCerts: Int

        public init(skipCerts: Int) {
            self.skipCerts = skipCerts
        }
    }
}

extension RFC_5280.InhibitAnyPolicy: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        .integer
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        let skipCerts = try Int(derEncoded: node, withIdentifier: identifier)
        guard skipCerts >= 0 else {
            throw ISO_8824.Error.invalidASN1Object(reason: "SkipCerts is INTEGER (0..MAX); got \(skipCerts)")
        }
        self.skipCerts = skipCerts
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        guard self.skipCerts >= 0 else {
            throw ISO_8824.Error.invalidASN1Object(reason: "SkipCerts is INTEGER (0..MAX); got \(self.skipCerts)")
        }
        try self.skipCerts.serialize(into: &coder, withIdentifier: identifier)
    }
}

extension RFC_5280.InhibitAnyPolicy {
    /// `id-ce-inhibitAnyPolicy` (§4.2.1.14).
    public static var extensionID: ISO_8824.ObjectIdentifier {
        RFC_5280.Extension.ID.inhibitAnyPolicy
    }

    /// Decodes the typed value from a generic ``RFC_5280/Extension``.
    public init(_ certificateExtension: RFC_5280.Extension) throws(ISO_8824.Error) {
        guard certificateExtension.extnID == Self.extensionID else {
            throw ISO_8824.Error.invalidASN1Object(reason: "Expected id-ce-inhibitAnyPolicy, got \(certificateExtension.extnID)")
        }
        self = try Self(derEncoded: certificateExtension.extnValue.bytes)
    }

    /// Wraps this value as a generic ``RFC_5280/Extension``.
    ///
    /// §4.2.1.14 criticality law: conforming CAs MUST mark this extension
    /// critical, hence the default.
    public func makeExtension(critical: Bool = true) throws(ISO_8824.Error) -> RFC_5280.Extension {
        var serializer = ISO_8825.DER.Serializer()
        try serializer.serialize(self)
        return RFC_5280.Extension(
            extnID: Self.extensionID,
            critical: critical,
            extnValue: ISO_8824.OctetString(contentBytes: serializer.serializedBytes[...])
        )
    }
}
