public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `AccessDescription ::= SEQUENCE { accessMethod OBJECT IDENTIFIER,
    /// accessLocation GeneralName }` (RFC 5280 §4.2.2.1).
    public struct AccessDescription: Hashable, Sendable {
        /// The access method (``RFC_5280/AccessDescription/ID``).
        public var accessMethod: ISO_8824.ObjectIdentifier

        /// Where the described information may be obtained.
        public var accessLocation: RFC_5280.GeneralName

        public init(accessMethod: ISO_8824.ObjectIdentifier, accessLocation: RFC_5280.GeneralName) {
            self.accessMethod = accessMethod
            self.accessLocation = accessLocation
        }
    }
}

extension RFC_5280.AccessDescription: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        self = try ISO_8825.DER.sequence(node, identifier: identifier) { (nodes: inout ISO_8825.Node.Collection.Iterator) throws(ISO_8824.Error) -> Self in
            let accessMethod = try ISO_8824.ObjectIdentifier(derEncoded: &nodes)
            let accessLocation = try RFC_5280.GeneralName(derEncoded: &nodes)
            return Self(accessMethod: accessMethod, accessLocation: accessLocation)
        }
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            try coder.serialize(self.accessMethod)
            try coder.serialize(self.accessLocation)
        }
    }
}
