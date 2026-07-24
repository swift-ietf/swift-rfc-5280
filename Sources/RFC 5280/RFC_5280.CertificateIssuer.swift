// RFC_5280.CertificateIssuer.swift
// RFC 5280 §5.3.3 — CRL Entry Extensions: Certificate Issuer
// https://www.rfc-editor.org/rfc/rfc5280#section-5.3.3

public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `CertificateIssuer ::= GeneralNames` (RFC 5280 §5.3.3).
    ///
    /// Identifies the certificate issuer associated with an entry in an
    /// indirect CRL. The issuer carries over: if this extension is absent
    /// from an entry, the entry's certificate issuer is the one from the
    /// previous entry, defaulting to the CRL issuer for the first entry.
    /// That carry-over is CRL-processing runtime law; this type carries the
    /// entry's wire law only.
    ///
    /// Criticality law: conforming CAs MUST mark this extension as critical
    /// — a relying party that ignored it would attribute a revocation to
    /// the wrong issuer.
    public struct CertificateIssuer: Hashable, Sendable {
        /// The issuer names, in wire order. Must contain at least one; the
        /// SIZE (1..MAX) bound is enforced at the wire boundary.
        public var names: [RFC_5280.GeneralName]

        public init(_ names: [RFC_5280.GeneralName]) {
            self.names = names
        }
    }
}

extension RFC_5280.CertificateIssuer {
    /// Whether the names satisfy §5.3.3: the entry's issuer is a
    /// distinguished name, so conforming CAs include exactly one
    /// `directoryName`.
    ///
    /// Other name forms are preserved for wire fidelity and reported here.
    public var isRFC5280Conformant: Bool {
        guard self.names.count == 1, let name = self.names.first else { return false }
        if case .directoryName = name { return true }
        return false
    }
}

extension RFC_5280.CertificateIssuer: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        let names = try ISO_8825.DER.sequence(
            of: RFC_5280.GeneralName.self,
            identifier: identifier,
            rootNode: node
        )
        guard !names.isEmpty else {
            throw ISO_8824.Error.invalidASN1Object(
                reason: "GeneralNames is SEQUENCE SIZE (1..MAX) OF GeneralName; got an empty sequence"
            )
        }
        self.names = names
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        guard !self.names.isEmpty else {
            throw ISO_8824.Error.invalidASN1Object(
                reason: "GeneralNames is SEQUENCE SIZE (1..MAX) OF GeneralName; got an empty sequence"
            )
        }
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            for name in self.names {
                try coder.serialize(name)
            }
        }
    }
}

extension RFC_5280.CertificateIssuer {
    /// `id-ce-certificateIssuer` (§5.3.3).
    public static var extensionID: ISO_8824.ObjectIdentifier {
        RFC_5280.Extension.ID.certificateIssuer
    }

    /// Decodes the typed value from a generic ``RFC_5280/Extension``.
    public init(_ certificateExtension: RFC_5280.Extension) throws(ISO_8824.Error) {
        guard certificateExtension.extnID == Self.extensionID else {
            throw ISO_8824.Error.invalidASN1Object(reason: "Expected id-ce-certificateIssuer, got \(certificateExtension.extnID)")
        }
        self = try Self(derEncoded: certificateExtension.extnValue.bytes)
    }

    /// Wraps this value as a generic ``RFC_5280/Extension``.
    ///
    /// §5.3.3 criticality law: conforming CAs MUST mark this extension
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
