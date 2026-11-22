public import ISO_8824
public import ISO_8825

extension IETF.RFC.`5280` {
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
        public var noticeRef: IETF.RFC.`5280`.NoticeReference?

        /// Notice text to display directly.
        public var explicitText: IETF.RFC.`5280`.DisplayText?

        public init(noticeRef: IETF.RFC.`5280`.NoticeReference? = nil, explicitText: IETF.RFC.`5280`.DisplayText? = nil) {
            self.noticeRef = noticeRef
            self.explicitText = explicitText
        }
    }
}

extension IETF.RFC.`5280`.UserNotice {
    /// Whether this value satisfies the §4.2.1.4 profile guidance: the
    /// `noticeRef` option is not used, and any explicit text respects the
    /// SIZE (1..200) bound.
    public var isRFC5280Conformant: Bool {
        guard self.noticeRef == nil else { return false }
        guard let explicitText = self.explicitText else { return true }
        return explicitText.isRFC5280Conformant
    }
}

extension IETF.RFC.`5280`.UserNotice: ISO.`8825`.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO.`8824`.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO.`8825`.Node, withIdentifier identifier: ISO.`8824`.Identifier) throws(ISO.`8824`.Error) {
        self = try ISO.`8825`.DER.sequence(node, identifier: identifier) { (nodes: inout ISO.`8825`.Node.Collection.Iterator) throws(ISO.`8824`.Error) -> Self in
            var noticeRef: IETF.RFC.`5280`.NoticeReference?
            var explicitText: IETF.RFC.`5280`.DisplayText?
            while let child = nodes.next() {
                if child.identifier == IETF.RFC.`5280`.NoticeReference.defaultIdentifier, noticeRef == nil, explicitText == nil {
                    noticeRef = try IETF.RFC.`5280`.NoticeReference(derEncoded: child)
                } else {
                    explicitText = try IETF.RFC.`5280`.DisplayText(derEncoded: child)
                }
            }
            return Self(noticeRef: noticeRef, explicitText: explicitText)
        }
    }

    public func serialize(into coder: inout ISO.`8825`.DER.Serializer, withIdentifier identifier: ISO.`8824`.Identifier) throws(ISO.`8824`.Error) {
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO.`8825`.DER.Serializer) throws(ISO.`8824`.Error) in
            if let noticeRef = self.noticeRef {
                try coder.serialize(noticeRef)
            }
            if let explicitText = self.explicitText {
                try coder.serialize(explicitText)
            }
        }
    }
}
