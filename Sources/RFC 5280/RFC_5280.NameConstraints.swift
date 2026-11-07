public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `NameConstraints ::= SEQUENCE { permittedSubtrees [0] GeneralSubtrees
    /// OPTIONAL, excludedSubtrees [1] GeneralSubtrees OPTIONAL }` with
    /// `GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree`
    /// (RFC 5280 §4.2.1.10).
    ///
    /// Criticality law: this extension MUST be used only in CA certificates,
    /// and conforming CAs MUST mark it critical. Wire law: conforming CAs
    /// MUST NOT issue certificates where this extension is an empty sequence
    /// — at least one of `permittedSubtrees` and `excludedSubtrees` MUST be
    /// present, and each present field must hold at least one subtree.
    /// The constraint-matching law per name form (§4.2.1.10) lives in
    /// ``RFC_5280/NameConstraints/DNSName``,
    /// ``RFC_5280/NameConstraints/IPAddress``, and
    /// ``RFC_5280/NameConstraints/URI``; *applying* those predicates across
    /// a certification path (subtree union, state tracking) is verifier
    /// runtime law.
    public struct NameConstraints: Hashable, Sendable {
        /// The permitted subtrees (`nil` means the field is absent).
        public var permittedSubtrees: [RFC_5280.GeneralSubtree]?

        /// The excluded subtrees (`nil` means the field is absent).
        public var excludedSubtrees: [RFC_5280.GeneralSubtree]?

        public init(permittedSubtrees: [RFC_5280.GeneralSubtree]? = nil, excludedSubtrees: [RFC_5280.GeneralSubtree]? = nil) {
            self.permittedSubtrees = permittedSubtrees
            self.excludedSubtrees = excludedSubtrees
        }
    }
}

extension RFC_5280.NameConstraints {
    /// Whether every subtree satisfies the §4.2.1.10 profile law — within
    /// this profile `minimum` MUST be zero and `maximum` MUST be absent.
    ///
    /// Subtrees violating either are preserved for wire fidelity; this
    /// reports their presence so a policy layer can act on it. See
    /// ``RFC_5280/GeneralSubtree/isRFC5280Conformant``.
    public var isRFC5280Conformant: Bool {
        let subtrees = (self.permittedSubtrees ?? []) + (self.excludedSubtrees ?? [])
        return subtrees.allSatisfy(\.isRFC5280Conformant)
    }
}

extension RFC_5280.NameConstraints: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        self = try ISO_8825.DER.sequence(node, identifier: identifier) { (nodes: inout ISO_8825.Node.Collection.Iterator) throws(ISO_8824.Error) -> Self in
            let permittedSubtrees = try ISO_8825.DER.optionalImplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) {
                (node: ISO_8825.Node) throws(ISO_8824.Error) -> [RFC_5280.GeneralSubtree] in
                try ISO_8825.DER.sequence(
                    of: RFC_5280.GeneralSubtree.self,
                    identifier: ISO_8824.Identifier(tagWithNumber: 0, tagClass: .contextSpecific),
                    rootNode: node
                )
            }
            let excludedSubtrees = try ISO_8825.DER.optionalImplicitlyTagged(&nodes, tagNumber: 1, tagClass: .contextSpecific) {
                (node: ISO_8825.Node) throws(ISO_8824.Error) -> [RFC_5280.GeneralSubtree] in
                try ISO_8825.DER.sequence(
                    of: RFC_5280.GeneralSubtree.self,
                    identifier: ISO_8824.Identifier(tagWithNumber: 1, tagClass: .contextSpecific),
                    rootNode: node
                )
            }
            guard permittedSubtrees != nil || excludedSubtrees != nil else {
                throw ISO_8824.Error.invalidASN1Object(reason: "NameConstraints must contain at least one of permittedSubtrees and excludedSubtrees")
            }
            guard permittedSubtrees.map({ !$0.isEmpty }) ?? true, excludedSubtrees.map({ !$0.isEmpty }) ?? true else {
                throw ISO_8824.Error.invalidASN1Object(reason: "GeneralSubtrees is SEQUENCE SIZE (1..MAX) OF GeneralSubtree; got an empty sequence")
            }
            return Self(permittedSubtrees: permittedSubtrees, excludedSubtrees: excludedSubtrees)
        }
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        guard self.permittedSubtrees != nil || self.excludedSubtrees != nil else {
            throw ISO_8824.Error.invalidASN1Object(reason: "NameConstraints must contain at least one of permittedSubtrees and excludedSubtrees")
        }
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            if let permittedSubtrees = self.permittedSubtrees {
                try coder.appendConstructedNode(identifier: ISO_8824.Identifier(tagWithNumber: 0, tagClass: .contextSpecific)) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
                    for subtree in permittedSubtrees {
                        try coder.serialize(subtree)
                    }
                }
            }
            if let excludedSubtrees = self.excludedSubtrees {
                try coder.appendConstructedNode(identifier: ISO_8824.Identifier(tagWithNumber: 1, tagClass: .contextSpecific)) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
                    for subtree in excludedSubtrees {
                        try coder.serialize(subtree)
                    }
                }
            }
        }
    }
}

extension RFC_5280.NameConstraints {
    /// `id-ce-nameConstraints` (§4.2.1.10).
    public static var extensionID: ISO_8824.ObjectIdentifier {
        RFC_5280.Extension.ID.nameConstraints
    }

    /// Decodes the typed value from a generic ``RFC_5280/Extension``.
    public init(_ certificateExtension: RFC_5280.Extension) throws(ISO_8824.Error) {
        guard certificateExtension.extnID == Self.extensionID else {
            throw ISO_8824.Error.invalidASN1Object(reason: "Expected id-ce-nameConstraints, got \(certificateExtension.extnID)")
        }
        self = try Self(derEncoded: certificateExtension.extnValue.bytes)
    }

    /// Wraps this value as a generic ``RFC_5280/Extension``.
    ///
    /// §4.2.1.10 criticality law: conforming CAs MUST mark this extension
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
