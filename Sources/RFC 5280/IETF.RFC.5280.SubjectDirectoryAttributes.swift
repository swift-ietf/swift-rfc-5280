public import ISO_8824
public import ISO_8825

extension IETF.RFC.`5280` {
    /// `SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF Attribute`
    /// (RFC 5280 §4.2.1.8).
    ///
    /// Conveys identification attributes of the subject — nationality, age,
    /// and the like. The profile defines no attribute types of its own here
    /// and the extension is not used for path validation.
    ///
    /// Criticality law: conforming CAs MUST mark this extension as
    /// non-critical.
    public struct SubjectDirectoryAttributes: Hashable, Sendable {
        /// The subject's directory attributes, in wire order. Must contain
        /// at least one; the SIZE (1..MAX) bound is enforced at the wire
        /// boundary.
        public var attributes: [IETF.RFC.`5280`.Attribute]

        public init(_ attributes: [IETF.RFC.`5280`.Attribute]) {
            self.attributes = attributes
        }
    }
}

extension IETF.RFC.`5280`.SubjectDirectoryAttributes: ISO.`8825`.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO.`8824`.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO.`8825`.Node, withIdentifier identifier: ISO.`8824`.Identifier) throws(ISO.`8824`.Error) {
        let attributes = try ISO.`8825`.DER.sequence(
            of: IETF.RFC.`5280`.Attribute.self,
            identifier: identifier,
            rootNode: node
        )
        guard !attributes.isEmpty else {
            throw ISO.`8824`.Error.invalidASN1Object(
                reason: "SubjectDirectoryAttributes is SEQUENCE SIZE (1..MAX) OF Attribute; got an empty sequence"
            )
        }
        self.attributes = attributes
    }

    public func serialize(into coder: inout ISO.`8825`.DER.Serializer, withIdentifier identifier: ISO.`8824`.Identifier) throws(ISO.`8824`.Error) {
        guard !self.attributes.isEmpty else {
            throw ISO.`8824`.Error.invalidASN1Object(
                reason: "SubjectDirectoryAttributes is SEQUENCE SIZE (1..MAX) OF Attribute; got an empty sequence"
            )
        }
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO.`8825`.DER.Serializer) throws(ISO.`8824`.Error) in
            for attribute in self.attributes {
                try coder.serialize(attribute)
            }
        }
    }
}

extension IETF.RFC.`5280`.SubjectDirectoryAttributes {
    /// `id-ce-subjectDirectoryAttributes` (§4.2.1.8).
    public static var extensionID: ISO.`8824`.ObjectIdentifier {
        IETF.RFC.`5280`.Extension.ID.subjectDirectoryAttributes
    }

    /// Decodes the typed value from a generic ``RFC_5280/Extension``.
    public init(_ certificateExtension: IETF.RFC.`5280`.Extension) throws(ISO.`8824`.Error) {
        guard certificateExtension.extnID == Self.extensionID else {
            throw ISO.`8824`.Error.invalidASN1Object(reason: "Expected id-ce-subjectDirectoryAttributes, got \(certificateExtension.extnID)")
        }
        self = try Self(derEncoded: certificateExtension.extnValue.bytes)
    }

    /// Wraps this value as a generic ``RFC_5280/Extension``.
    ///
    /// §4.2.1.8 criticality law: conforming CAs MUST mark this extension
    /// non-critical, hence the default.
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
