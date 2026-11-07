public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE,
    /// pathLenConstraint INTEGER (0..MAX) OPTIONAL }` (RFC 5280 §4.2.1.9).
    ///
    /// Criticality law: conforming CAs MUST include this extension in all CA
    /// certificates that contain public keys used to validate certificate
    /// signatures, and MUST mark it critical in such certificates.
    /// `pathLenConstraint` is meaningful only when `cA` is TRUE and the
    /// certificate's key usage asserts `keyCertSign`; CAs MUST NOT include a
    /// `pathLenConstraint` otherwise.
    public struct BasicConstraints: Hashable, Sendable {
        /// Whether the certified public key may be used to verify
        /// certificate signatures (the subject is a CA).
        public var isCA: Bool

        /// The maximum number of non-self-issued intermediate certificates
        /// that may follow this certificate in a valid certification path.
        public var pathLenConstraint: Int?

        public init(isCA: Bool, pathLenConstraint: Int? = nil) {
            self.isCA = isCA
            self.pathLenConstraint = pathLenConstraint
        }
    }
}

extension RFC_5280.BasicConstraints: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        self = try ISO_8825.DER.sequence(node, identifier: identifier) { (nodes: inout ISO_8825.Node.Collection.Iterator) throws(ISO_8824.Error) -> Self in
            let isCA = try ISO_8825.DER.decodeDefault(&nodes, defaultValue: false)
            let pathLenConstraint: Int? = try ISO_8825.DER.optionalImplicitlyTagged(&nodes)
            if let pathLenConstraint {
                guard pathLenConstraint >= 0 else {
                    throw ISO_8824.Error.invalidASN1Object(reason: "pathLenConstraint is INTEGER (0..MAX); got \(pathLenConstraint)")
                }
            }
            return Self(isCA: isCA, pathLenConstraint: pathLenConstraint)
        }
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            if self.isCA {
                try coder.serialize(true)
            }
            if let pathLenConstraint = self.pathLenConstraint {
                guard pathLenConstraint >= 0 else {
                    throw ISO_8824.Error.invalidASN1Object(reason: "pathLenConstraint is INTEGER (0..MAX); got \(pathLenConstraint)")
                }
                try coder.serialize(pathLenConstraint)
            }
        }
    }
}

extension RFC_5280.BasicConstraints {
    /// `id-ce-basicConstraints` (§4.2.1.9).
    public static var extensionID: ISO_8824.ObjectIdentifier {
        RFC_5280.Extension.ID.basicConstraints
    }

    /// Decodes the typed value from a generic ``RFC_5280/Extension``.
    public init(_ certificateExtension: RFC_5280.Extension) throws(ISO_8824.Error) {
        guard certificateExtension.extnID == Self.extensionID else {
            throw ISO_8824.Error.invalidASN1Object(reason: "Expected id-ce-basicConstraints, got \(certificateExtension.extnID)")
        }
        self = try Self(derEncoded: certificateExtension.extnValue.bytes)
    }

    /// Wraps this value as a generic ``RFC_5280/Extension``.
    ///
    /// §4.2.1.9 criticality law: CA certificates whose key validates
    /// signatures MUST mark this extension critical, hence the default.
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
