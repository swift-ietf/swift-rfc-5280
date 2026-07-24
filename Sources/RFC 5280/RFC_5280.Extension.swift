// RFC_5280.Extension.swift
// RFC 5280 §4.2 — Certificate Extensions
// https://www.rfc-editor.org/rfc/rfc5280#section-4.2

public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `Extension ::= SEQUENCE { extnID OBJECT IDENTIFIER, critical BOOLEAN
    /// DEFAULT FALSE, extnValue OCTET STRING }` (RFC 5280 §4.2).
    ///
    /// The `extnValue` OCTET STRING wraps the DER encoding of the
    /// extension-specific value. Criticality law: a certificate-using system
    /// MUST reject a certificate containing a critical extension it does not
    /// recognize, and MUST process every recognized extension regardless of
    /// criticality. DER law: `critical` is `DEFAULT FALSE`, so a false value
    /// MUST be omitted from the encoding (and an encoded false is rejected
    /// on parse by the substrate's DEFAULT handling).
    public struct Extension: Hashable, Sendable {
        /// The OBJECT IDENTIFIER naming the extension.
        public var extnID: ISO_8824.ObjectIdentifier

        /// Whether the extension is critical (§4.2 criticality law).
        public var critical: Bool

        /// The DER encoding of the extension value, wrapped in the wire's
        /// OCTET STRING.
        public var extnValue: ISO_8824.OctetString

        public init(extnID: ISO_8824.ObjectIdentifier, critical: Bool, extnValue: ISO_8824.OctetString) {
            self.extnID = extnID
            self.critical = critical
            self.extnValue = extnValue
        }
    }
}

extension RFC_5280.Extension: ISO_8825.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        self = try ISO_8825.DER.sequence(node, identifier: identifier) { (nodes: inout ISO_8825.Node.Collection.Iterator) throws(ISO_8824.Error) -> Self in
            let extnID = try ISO_8824.ObjectIdentifier(derEncoded: &nodes)
            let critical = try ISO_8825.DER.decodeDefault(&nodes, defaultValue: false)
            let extnValue = try ISO_8824.OctetString(derEncoded: &nodes)
            return Self(extnID: extnID, critical: critical, extnValue: extnValue)
        }
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) in
            try coder.serialize(self.extnID)
            if self.critical {
                try coder.serialize(true)
            }
            try coder.serialize(self.extnValue)
        }
    }
}
