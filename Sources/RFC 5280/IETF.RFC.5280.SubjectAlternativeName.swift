public import ISO_8824
public import ISO_8825

extension IETF.RFC.`5280` {
    /// `SubjectAltName ::= GeneralNames` with `GeneralNames ::= SEQUENCE
    /// SIZE (1..MAX) OF GeneralName` (RFC 5280 §4.2.1.6).
    ///
    /// Criticality law: when the certificate's `subject` is an empty
    /// sequence, this extension MUST be present and MUST be critical;
    /// otherwise conforming CAs SHOULD mark it non-critical. Value law:
    /// name forms MUST NOT be empty (for example a zero-length `dNSName`
    /// or the space-only legacy convention MUST NOT be used), and address
    /// or name values MUST use their canonical wire forms as documented on
    /// ``RFC_5280/GeneralName``.
    public struct SubjectAlternativeName: Hashable, Sendable {
        /// The alternative names, in wire order. Must contain at least one
        /// name; the SIZE (1..MAX) bound is enforced at the wire boundary.
        public var names: [IETF.RFC.`5280`.GeneralName]

        public init(_ names: [IETF.RFC.`5280`.GeneralName]) {
            self.names = names
        }
    }
}

extension IETF.RFC.`5280`.SubjectAlternativeName: ISO.`8825`.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO.`8824`.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO.`8825`.Node, withIdentifier identifier: ISO.`8824`.Identifier) throws(ISO.`8824`.Error) {
        let names = try ISO.`8825`.DER.sequence(
            of: IETF.RFC.`5280`.GeneralName.self,
            identifier: identifier,
            rootNode: node
        )
        guard !names.isEmpty else {
            throw ISO.`8824`.Error.invalidASN1Object(reason: "GeneralNames is SEQUENCE SIZE (1..MAX) OF GeneralName; got an empty sequence")
        }
        self.names = names
    }

    public func serialize(into coder: inout ISO.`8825`.DER.Serializer, withIdentifier identifier: ISO.`8824`.Identifier) throws(ISO.`8824`.Error) {
        guard !self.names.isEmpty else {
            throw ISO.`8824`.Error.invalidASN1Object(reason: "GeneralNames is SEQUENCE SIZE (1..MAX) OF GeneralName; got an empty sequence")
        }
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO.`8825`.DER.Serializer) throws(ISO.`8824`.Error) in
            for name in self.names {
                try coder.serialize(name)
            }
        }
    }
}

extension IETF.RFC.`5280`.SubjectAlternativeName {
    /// `id-ce-subjectAltName` (§4.2.1.6).
    public static var extensionID: ISO.`8824`.ObjectIdentifier {
        IETF.RFC.`5280`.Extension.ID.subjectAlternativeName
    }

    /// Decodes the typed value from a generic ``RFC_5280/Extension``.
    public init(_ certificateExtension: IETF.RFC.`5280`.Extension) throws(ISO.`8824`.Error) {
        guard certificateExtension.extnID == Self.extensionID else {
            throw ISO.`8824`.Error.invalidASN1Object(reason: "Expected id-ce-subjectAltName, got \(certificateExtension.extnID)")
        }
        self = try Self(derEncoded: certificateExtension.extnValue.bytes)
    }

    /// Wraps this value as a generic ``RFC_5280/Extension``.
    ///
    /// §4.2.1.6 criticality law: SHOULD be non-critical, unless the
    /// certificate's subject is empty, in which case it MUST be critical —
    /// pass `critical: true` for empty-subject certificates.
    public func makeExtension(critical: Bool = false) throws(ISO.`8824`.Error) -> IETF.RFC.`5280`.Extension {
        var serializer = ISO.`8825`.DER.Serializer()
        try serializer.serialize(self)
        return IETF.RFC.`5280`.Extension(
            extnID: Self.extensionID,
            critical: critical,
            extnValue: ISO.`8824`.OctetString(contentBytes: serializer.serializedBytes[...])
        )
    }
}
