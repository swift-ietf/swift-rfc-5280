public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `PolicyQualifierInfo ::= SEQUENCE { policyQualifierId
    /// PolicyQualifierId, qualifier ANY DEFINED BY policyQualifierId }`
    /// (RFC 5280 §4.2.1.4).
    ///
    /// The profile defines two qualifier types — `id-qt-cps`, whose
    /// qualifier is a `CPSuri` (`IA5String`), and `id-qt-unotice`, whose
    /// qualifier is a ``RFC_5280/UserNotice``. Because the field is
    /// `ANY DEFINED BY`, the value is preserved exactly as encoded and the
    /// typed views are offered on demand by ``cpsURI()`` and
    /// ``userNotice()``.
    ///
    /// Profile law: conforming CAs SHOULD use only the two qualifier types
    /// defined here, and SHOULD NOT use qualifiers at all when a policy can
    /// be identified by OID alone.
    public struct PolicyQualifierInfo: Hashable, Sendable {
        /// The OBJECT IDENTIFIER naming the qualifier's syntax.
        public var policyQualifierID: ISO_8824.ObjectIdentifier

        /// The qualifier value, exactly as encoded.
        public var qualifier: ISO_8825.`Any`

        public init(policyQualifierID: ISO_8824.ObjectIdentifier, qualifier: ISO_8825.`Any`) {
            self.policyQualifierID = policyQualifierID
            self.qualifier = qualifier
        }
    }
}

extension RFC_5280.PolicyQualifierInfo {
    /// Interprets the qualifier as a `CPSuri` (`IA5String`).
    ///
    /// Throws when the qualifier is not an `IA5String`; check
    /// ``policyQualifierID`` against ``ID/cps`` first.
    public func cpsURI() throws(ISO_8824.Error) -> ISO_8824.IA5String {
        try ISO_8824.IA5String(asn1Any: self.qualifier)
    }

    /// Interprets the qualifier as a ``RFC_5280/UserNotice``.
    ///
    /// Throws when the qualifier is not a `UserNotice`; check
    /// ``policyQualifierID`` against ``ID/unotice`` first.
    public func userNotice() throws(ISO_8824.Error) -> RFC_5280.UserNotice {
        try RFC_5280.UserNotice(asn1Any: self.qualifier)
    }

    /// Whether ``policyQualifierID`` is one of the two types the profile
    /// defines (§4.2.1.4).
    public var isRFC5280Conformant: Bool {
        self.policyQualifierID == RFC_5280.PolicyQualifierInfo.ID.cps
            || self.policyQualifierID == RFC_5280.PolicyQualifierInfo.ID.unotice
    }
}

extension RFC_5280.PolicyQualifierInfo: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        self = try ISO_8825.DER.sequence(node, identifier: identifier) { (nodes: inout ISO_8825.Node.Collection.Iterator) throws(ISO_8824.Error) -> Self in
            let policyQualifierID = try ISO_8824.ObjectIdentifier(derEncoded: &nodes)
            guard let qualifierNode = nodes.next() else {
                throw ISO_8824.Error.invalidASN1Object(reason: "PolicyQualifierInfo is missing its qualifier")
            }
            return Self(policyQualifierID: policyQualifierID, qualifier: ISO_8825.`Any`(derEncoded: qualifierNode))
        }
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            try coder.serialize(self.policyQualifierID)
            try coder.serialize(self.qualifier)
        }
    }
}
