// RFC_5280.AuthorityInformationAccess.swift
// RFC 5280 §4.2.2.1 — Authority Information Access
// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.2.1

public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF
    /// AccessDescription` (RFC 5280 §4.2.2.1).
    ///
    /// Criticality law: conforming CAs MUST mark this extension
    /// non-critical.
    public struct AuthorityInformationAccess: Hashable, Sendable {
        /// The access descriptions, in wire order. Must contain at least
        /// one; the SIZE (1..MAX) bound is enforced at the wire boundary.
        public var descriptions: [RFC_5280.AccessDescription]

        public init(_ descriptions: [RFC_5280.AccessDescription]) {
            self.descriptions = descriptions
        }
    }
}

extension RFC_5280.AuthorityInformationAccess: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        let descriptions = try ISO_8825.DER.sequence(
            of: RFC_5280.AccessDescription.self,
            identifier: identifier,
            rootNode: node
        )
        guard !descriptions.isEmpty else {
            throw ISO_8824.Error.invalidASN1Object(reason: "AuthorityInfoAccessSyntax is SEQUENCE SIZE (1..MAX) OF AccessDescription; got an empty sequence")
        }
        self.descriptions = descriptions
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        guard !self.descriptions.isEmpty else {
            throw ISO_8824.Error.invalidASN1Object(reason: "AuthorityInfoAccessSyntax is SEQUENCE SIZE (1..MAX) OF AccessDescription; got an empty sequence")
        }
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            for description in self.descriptions {
                try coder.serialize(description)
            }
        }
    }
}

extension RFC_5280.AuthorityInformationAccess {
    /// `id-pe-authorityInfoAccess` (§4.2.2.1).
    public static var extensionID: ISO_8824.ObjectIdentifier {
        RFC_5280.Extension.ID.authorityInformationAccess
    }

    /// Decodes the typed value from a generic ``RFC_5280/Extension``.
    public init(_ certificateExtension: RFC_5280.Extension) throws(ISO_8824.Error) {
        guard certificateExtension.extnID == Self.extensionID else {
            throw ISO_8824.Error.invalidASN1Object(reason: "Expected id-pe-authorityInfoAccess, got \(certificateExtension.extnID)")
        }
        self = try Self(derEncoded: certificateExtension.extnValue.bytes)
    }

    /// Wraps this value as a generic ``RFC_5280/Extension``.
    ///
    /// §4.2.2.1 criticality law: conforming CAs MUST mark this extension
    /// non-critical, hence the default.
    public func makeExtension(critical: Bool = false) throws(ISO_8824.Error) -> RFC_5280.Extension {
        var serializer = ISO_8825.DER.Serializer()
        try serializer.serialize(self)
        return RFC_5280.Extension(
            extnID: Self.extensionID,
            critical: critical,
            extnValue: ISO_8824.OctetString(contentBytes: serializer.serializedBytes[...])
        )
    }
}
