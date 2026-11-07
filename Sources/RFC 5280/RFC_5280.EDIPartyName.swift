public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `EDIPartyName ::= SEQUENCE { nameAssigner [0] DirectoryString OPTIONAL,
    /// partyName [1] DirectoryString }` (RFC 5280 §4.2.1.6, Appendix A.2).
    ///
    /// Both fields tag a CHOICE (`DirectoryString`), so despite the module's
    /// IMPLICIT TAGS default the context tags here are explicit by ASN.1 rule.
    public struct EDIPartyName: Hashable, Sendable {
        public var nameAssigner: RFC_5280.DirectoryString?
        public var partyName: RFC_5280.DirectoryString

        public init(nameAssigner: RFC_5280.DirectoryString? = nil, partyName: RFC_5280.DirectoryString) {
            self.nameAssigner = nameAssigner
            self.partyName = partyName
        }
    }
}

extension RFC_5280.EDIPartyName: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        self = try ISO_8825.DER.sequence(node, identifier: identifier) { (nodes: inout ISO_8825.Node.Collection.Iterator) throws(ISO_8824.Error) -> Self in
            let nameAssigner = try ISO_8825.DER.optionalExplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) { node throws(ISO_8824.Error) in
                try RFC_5280.DirectoryString(derEncoded: node)
            }
            let partyName = try ISO_8825.DER.explicitlyTagged(&nodes, tagNumber: 1, tagClass: .contextSpecific) { node throws(ISO_8824.Error) in
                try RFC_5280.DirectoryString(derEncoded: node)
            }
            return Self(nameAssigner: nameAssigner, partyName: partyName)
        }
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            if let nameAssigner = self.nameAssigner {
                try coder.serialize(nameAssigner, explicitlyTaggedWithTagNumber: 0, tagClass: .contextSpecific)
            }
            try coder.serialize(self.partyName, explicitlyTaggedWithTagNumber: 1, tagClass: .contextSpecific)
        }
    }
}
