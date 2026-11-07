public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `UserNotice ::= SEQUENCE { noticeRef NoticeReference OPTIONAL,
    /// explicitText DisplayText OPTIONAL }` (RFC 5280 §4.2.1.4).
    ///
    /// The qualifier for the `id-qt-unotice` policy qualifier: notice text
    /// intended for display to a relying party when a certificate is used.
    /// Both fields are optional and untagged, so they are told apart on the
    /// wire by type — `noticeRef` is a SEQUENCE, `explicitText` a character
    /// string.
    ///
    /// Profile law: conforming CAs SHOULD NOT use the `noticeRef` option.
    public struct UserNotice: Hashable, Sendable {
        /// A reference to a notice published elsewhere by an organization.
        public var noticeRef: RFC_5280.NoticeReference?

        /// Notice text to display directly.
        public var explicitText: RFC_5280.DisplayText?

        public init(noticeRef: RFC_5280.NoticeReference? = nil, explicitText: RFC_5280.DisplayText? = nil) {
            self.noticeRef = noticeRef
            self.explicitText = explicitText
        }
    }
}

extension RFC_5280.UserNotice {
    /// Whether this value satisfies the §4.2.1.4 profile guidance: the
    /// `noticeRef` option is not used, and any explicit text respects the
    /// SIZE (1..200) bound.
    public var isRFC5280Conformant: Bool {
        guard self.noticeRef == nil else { return false }
        guard let explicitText = self.explicitText else { return true }
        return explicitText.isRFC5280Conformant
    }
}

extension RFC_5280.UserNotice: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        self = try ISO_8825.DER.sequence(node, identifier: identifier) { (nodes: inout ISO_8825.Node.Collection.Iterator) throws(ISO_8824.Error) -> Self in
            var noticeRef: RFC_5280.NoticeReference?
            var explicitText: RFC_5280.DisplayText?
            while let child = nodes.next() {
                if child.identifier == RFC_5280.NoticeReference.defaultIdentifier, noticeRef == nil, explicitText == nil {
                    noticeRef = try RFC_5280.NoticeReference(derEncoded: child)
                } else {
                    explicitText = try RFC_5280.DisplayText(derEncoded: child)
                }
            }
            return Self(noticeRef: noticeRef, explicitText: explicitText)
        }
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            if let noticeRef = self.noticeRef {
                try coder.serialize(noticeRef)
            }
            if let explicitText = self.explicitText {
                try coder.serialize(explicitText)
            }
        }
    }
}
