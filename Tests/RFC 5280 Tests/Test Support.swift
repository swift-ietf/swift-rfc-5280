// Test Support.swift

import ISO_8824
import ISO_8825

@testable import RFC_5280

/// Serializes a value to its DER byte representation.
func derBytes(of value: some ISO_8825.DER.Serializable) throws(ISO_8824.Error) -> [UInt8] {
    var serializer = ISO_8825.DER.Serializer()
    try serializer.serialize(value)
    return serializer.serializedBytes
}

/// Asserts serialize → parse → serialize is the identity for a value.
func roundTrips<T: ISO_8825.DER.Parseable & ISO_8825.DER.Serializable & Equatable>(_ value: T) throws(ISO_8824.Error) -> Bool {
    let bytes = try derBytes(of: value)
    let reparsed = try T(derEncoded: bytes)
    let reserialized = try derBytes(of: reparsed)
    return reparsed == value && reserialized == bytes
}
