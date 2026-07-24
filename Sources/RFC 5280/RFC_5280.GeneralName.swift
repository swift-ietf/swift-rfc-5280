// RFC_5280.GeneralName.swift
// RFC 5280 §4.2.1.6 — Subject Alternative Name: GeneralName
// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.6

public import ISO_8824
public import ISO_8825

extension RFC_5280 {
    /// `GeneralName ::= CHOICE { otherName [0] OtherName, rfc822Name [1]
    /// IA5String, dNSName [2] IA5String, x400Address [3] ORAddress,
    /// directoryName [4] Name, ediPartyName [5] EDIPartyName,
    /// uniformResourceIdentifier [6] IA5String, iPAddress [7] OCTET STRING,
    /// registeredID [8] OBJECT IDENTIFIER }` (RFC 5280 §4.2.1.6,
    /// Appendix A.2 — IMPLICIT TAGS).
    ///
    /// Tagging law: all arms are implicitly tagged except `directoryName`,
    /// whose target (`Name`) is a CHOICE and therefore takes an explicit tag
    /// by ASN.1 rule. The X.400 `ORAddress` structure is outside this
    /// profile's law; its arm preserves the encoded value opaquely so
    /// certificates containing one still round-trip byte-for-byte.
    ///
    /// Value law (owned here as wire law, enforced by verifiers):
    /// `dNSName` uses the RFC 1034/1123 *preferred name syntax* with IA5
    /// (ASCII) labels — internationalized names are carried as A-labels;
    /// `iPAddress` is the raw network-byte-order address, 4 octets for IPv4
    /// and 16 for IPv6 (name-constraint contexts append an equal-length
    /// mask, making 8 or 32); `uniformResourceIdentifier` MUST include a
    /// scheme and be absolute.
    public enum GeneralName: Hashable, Sendable {
        case otherName(RFC_5280.OtherName)
        case rfc822Name(ISO_8824.IA5String)
        case dNSName(ISO_8824.IA5String)
        case x400Address(ISO_8825.`Any`)
        case directoryName(RFC_5280.Name)
        case ediPartyName(RFC_5280.EDIPartyName)
        case uniformResourceIdentifier(ISO_8824.IA5String)
        case iPAddress(ISO_8824.OctetString)
        case registeredID(ISO_8824.ObjectIdentifier)
    }
}

extension RFC_5280.GeneralName: ISO_8825.DER.Parseable, ISO_8825.DER.Serializable {
    public init(derEncoded node: ISO_8825.Node) throws(ISO_8824.Error) {
        guard node.identifier.tagClass == .contextSpecific else {
            throw ISO_8824.Error.unexpectedFieldType(node.identifier)
        }

        switch node.identifier.tagNumber {
        case 0:
            self = .otherName(try RFC_5280.OtherName(derEncoded: node, withIdentifier: node.identifier))
        case 1:
            self = .rfc822Name(try ISO_8824.IA5String(derEncoded: node, withIdentifier: node.identifier))
        case 2:
            self = .dNSName(try ISO_8824.IA5String(derEncoded: node, withIdentifier: node.identifier))
        case 3:
            self = .x400Address(ISO_8825.`Any`(derEncoded: node))
        case 4:
            // Explicit tag by ASN.1 rule: the constructed [4] wraps the Name.
            guard case .constructed(let children) = node.content else {
                throw ISO_8824.Error.invalidASN1Object(reason: "directoryName explicit tag must be constructed")
            }
            var iterator = children.makeIterator()
            guard let child = iterator.next(), iterator.next() == nil else {
                throw ISO_8824.Error.invalidASN1Object(reason: "directoryName explicit tag must wrap exactly one Name")
            }
            self = .directoryName(try RFC_5280.Name(derEncoded: child))
        case 5:
            self = .ediPartyName(try RFC_5280.EDIPartyName(derEncoded: node, withIdentifier: node.identifier))
        case 6:
            self = .uniformResourceIdentifier(try ISO_8824.IA5String(derEncoded: node, withIdentifier: node.identifier))
        case 7:
            self = .iPAddress(try ISO_8824.OctetString(derEncoded: node, withIdentifier: node.identifier))
        case 8:
            self = .registeredID(try ISO_8824.ObjectIdentifier(derEncoded: node, withIdentifier: node.identifier))
        default:
            throw ISO_8824.Error.unexpectedFieldType(node.identifier)
        }
    }

    public func serialize(into coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) {
        switch self {
        case .otherName(let name):
            try name.serialize(into: &coder, withIdentifier: ISO_8824.Identifier(tagWithNumber: 0, tagClass: .contextSpecific))
        case .rfc822Name(let name):
            try name.serialize(into: &coder, withIdentifier: ISO_8824.Identifier(tagWithNumber: 1, tagClass: .contextSpecific))
        case .dNSName(let name):
            try name.serialize(into: &coder, withIdentifier: ISO_8824.Identifier(tagWithNumber: 2, tagClass: .contextSpecific))
        case .x400Address(let address):
            try coder.serialize(address)
        case .directoryName(let name):
            try coder.serialize(name, explicitlyTaggedWithTagNumber: 4, tagClass: .contextSpecific)
        case .ediPartyName(let name):
            try name.serialize(into: &coder, withIdentifier: ISO_8824.Identifier(tagWithNumber: 5, tagClass: .contextSpecific))
        case .uniformResourceIdentifier(let uri):
            try uri.serialize(into: &coder, withIdentifier: ISO_8824.Identifier(tagWithNumber: 6, tagClass: .contextSpecific))
        case .iPAddress(let address):
            try address.serialize(into: &coder, withIdentifier: ISO_8824.Identifier(tagWithNumber: 7, tagClass: .contextSpecific))
        case .registeredID(let oid):
            try oid.serialize(into: &coder, withIdentifier: ISO_8824.Identifier(tagWithNumber: 8, tagClass: .contextSpecific))
        }
    }
}
