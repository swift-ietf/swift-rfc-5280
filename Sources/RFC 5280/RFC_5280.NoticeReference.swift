// RFC_5280.NoticeReference.swift
// RFC 5280 §4.2.1.4 — Certificate Policies: NoticeReference
// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.4

public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `NoticeReference ::= SEQUENCE { organization DisplayText,
    /// noticeNumbers SEQUENCE OF INTEGER }` (RFC 5280 §4.2.1.4).
    ///
    /// Names an organization and a sequence of notice numbers within a
    /// notice file that organization publishes; resolving the reference to
    /// notice text is out of scope for the profile.
    public struct NoticeReference: Hashable, Sendable {
        /// The organization that publishes the referenced notice file.
        public var organization: RFC_5280.DisplayText

        /// The notice numbers within that file.
        public var noticeNumbers: [Int]

        public init(organization: RFC_5280.DisplayText, noticeNumbers: [Int]) {
            self.organization = organization
            self.noticeNumbers = noticeNumbers
        }
    }
}

extension RFC_5280.NoticeReference: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        self = try ISO_8825.DER.sequence(node, identifier: identifier) { (nodes: inout ISO_8825.Node.Collection.Iterator) throws(ISO_8824.Error) -> Self in
            let organization = try RFC_5280.DisplayText(derEncoded: &nodes)
            let noticeNumbers = try ISO_8825.DER.sequence(of: Int.self, identifier: .sequence, nodes: &nodes)
            return Self(organization: organization, noticeNumbers: noticeNumbers)
        }
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            try coder.serialize(self.organization)
            try coder.appendConstructedNode(identifier: .sequence) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
                for number in self.noticeNumbers {
                    try coder.serialize(number)
                }
            }
        }
    }
}
