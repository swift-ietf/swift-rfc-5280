public import ISO_8824
public import ISO_8825

extension IETF.RFC.`5280` {
    /// `Validity ::= SEQUENCE { notBefore Time, notAfter Time }`
    /// (RFC 5280 §4.1.2.5).
    ///
    /// A certificate with no well-defined expiration date carries the
    /// sentinel `notAfter` value `99991231235959Z`
    /// (``hasNoWellDefinedExpiration``). Evaluating whether a presented
    /// certificate falls inside its validity interval is verifier runtime
    /// policy; this type carries the interval's wire law only.
    public struct Validity: Hashable, Sendable {
        public var notBefore: IETF.RFC.`5280`.Time
        public var notAfter: IETF.RFC.`5280`.Time

        public init(notBefore: IETF.RFC.`5280`.Time, notAfter: IETF.RFC.`5280`.Time) {
            self.notBefore = notBefore
            self.notAfter = notAfter
        }
    }
}

extension IETF.RFC.`5280`.Validity {
    /// Whether `notAfter` is the §4.1.2.5 `99991231235959Z` sentinel for
    /// a certificate with no well-defined expiration date.
    public var hasNoWellDefinedExpiration: Bool {
        guard case .generalTime(let time) = self.notAfter else { return false }
        return time.year == 9999
            && time.month == 12
            && time.day == 31
            && time.hours == 23
            && time.minutes == 59
            && time.seconds == 59
            && time.rawFractionalSeconds.isEmpty
    }
}

extension IETF.RFC.`5280`.Validity: ISO.`8825`.DER.ImplicitlyTaggable {
    public static var defaultIdentifier: ISO.`8824`.Identifier {
        .sequence
    }

    public init(derEncoded node: ISO.`8825`.Node, withIdentifier identifier: ISO.`8824`.Identifier) throws(ISO.`8824`.Error) {
        self = try ISO.`8825`.DER.sequence(node, identifier: identifier) { (nodes: inout ISO.`8825`.Node.Collection.Iterator) throws(ISO.`8824`.Error) -> Self in
            let notBefore = try IETF.RFC.`5280`.Time(derEncoded: &nodes)
            let notAfter = try IETF.RFC.`5280`.Time(derEncoded: &nodes)
            return Self(notBefore: notBefore, notAfter: notAfter)
        }
    }

    public func serialize(into coder: inout ISO.`8825`.DER.Serializer, withIdentifier identifier: ISO.`8824`.Identifier) throws(ISO.`8824`.Error) {
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO.`8825`.DER.Serializer) throws(ISO.`8824`.Error) in
            try coder.serialize(self.notBefore)
            try coder.serialize(self.notAfter)
        }
    }
}
