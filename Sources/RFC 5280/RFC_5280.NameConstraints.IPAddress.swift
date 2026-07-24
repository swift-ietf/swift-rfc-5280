// RFC_5280.NameConstraints.IPAddress.swift
// RFC 5280 §4.2.1.10 — Name Constraints: iPAddress matching law
// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.10

// The IPv4/IPv6 address parsers take the byte-domain `Byte` substrate
// ([API-BYTE-003]); ASN.1 octet content is stdlib `UInt8`, so this file
// bridges at its own call site ([API-BYTE-008]) and needs `Byte` directly.
private import Byte_Primitives
public import ISO_8824
public import RFC_4291
public import RFC_791

extension RFC_5280.NameConstraints {
    /// The §4.2.1.10 constraint form for the `iPAddress` name form: an
    /// address range as a base address plus a mask.
    ///
    /// "For IPv4 addresses, the iPAddress field of GeneralName MUST contain
    /// eight (8) octets, encoded in the style of RFC 4632 (CIDR) to
    /// represent an address range. For IPv6 addresses, the iPAddress field
    /// MUST contain 32 octets similarly encoded." (§4.2.1.10)
    ///
    /// The wire form is the base address octets followed by an equal number
    /// of mask octets, both in network byte order. Address value law belongs
    /// to ``RFC_791`` and ``RFC_4291``; this
    /// type owns the profile's range law. RFC 4632 style requires the mask
    /// to be a contiguous run of one-bits followed by zero-bits; because
    /// non-conforming constraints exist in the wild, any equal-halves split
    /// is preserved and the CIDR judgment reported separately via
    /// ``isCIDRConformant``.
    public enum IPAddress: Hashable, Sendable {
        case v4(base: RFC_791.IPv4.Address, mask: RFC_791.IPv4.Address)
        case v6(base: RFC_4291.IPv6.Address, mask: RFC_4291.IPv6.Address)
    }
}

extension RFC_5280.NameConstraints.IPAddress {
    /// Splits the constraint's `iPAddress` content octets into base and
    /// mask halves.
    ///
    /// §4.2.1.10 length law: 8 octets for an IPv4 range, 32 for IPv6;
    /// any other length is rejected.
    public init(constraint: ISO_8824.OctetString) throws(ISO_8824.Error) {
        let octets = constraint.bytes
        switch octets.count {
        case 8:
            do throws(RFC_791.IPv4.Address.Error) {
                self = .v4(
                    base: try RFC_791.IPv4.Address(binary: Self.byteDomain(octets.prefix(4))),
                    mask: try RFC_791.IPv4.Address(binary: Self.byteDomain(octets.suffix(4)))
                )
            } catch {
                throw ISO_8824.Error.invalidASN1Object(reason: "Malformed IPv4 iPAddress name constraint")
            }
        case 32:
            do throws(RFC_4291.IPv6.Address.Error) {
                self = .v6(
                    base: try RFC_4291.IPv6.Address(binary: Self.byteDomain(octets.prefix(16))),
                    mask: try RFC_4291.IPv6.Address(binary: Self.byteDomain(octets.suffix(16)))
                )
            } catch {
                throw ISO_8824.Error.invalidASN1Object(reason: "Malformed IPv6 iPAddress name constraint")
            }
        default:
            throw ISO_8824.Error.invalidASN1Object(
                reason: "An iPAddress name constraint is 8 octets (IPv4) or 32 octets (IPv6); got \(octets.count)"
            )
        }
    }

    /// Whether this constraint describes an IPv4 range.
    public var isIPv4: Bool {
        if case .v4 = self { return true }
        return false
    }

    /// Whether the IPv4 `address` falls inside this range. An IPv6-family
    /// constraint never matches an IPv4 address.
    public func contains(_ address: RFC_791.IPv4.Address) -> Bool {
        guard case .v4(let base, let mask) = self else { return false }
        let maskBits = Self.hostOrder(mask)
        return Self.hostOrder(address) & maskBits == Self.hostOrder(base) & maskBits
    }

    /// Whether the IPv6 `address` falls inside this range. An IPv4-family
    /// constraint never matches an IPv6 address.
    public func contains(_ address: RFC_4291.IPv6.Address) -> Bool {
        guard case .v6(let base, let mask) = self else { return false }
        let pairs = zip(
            zip(Self.segments(of: address), Self.segments(of: base)),
            Self.segments(of: mask)
        )
        return pairs.allSatisfy { segments, maskSegment in
            segments.0 & maskSegment == segments.1 & maskSegment
        }
    }

    /// Whether `address` — the raw network-byte-order octets of an
    /// `iPAddress` GeneralName (4 for IPv4, 16 for IPv6) — falls inside
    /// this range. An address of a different family than the constraint
    /// never matches.
    public func contains(_ address: ArraySlice<UInt8>) -> Bool {
        // A malformed or wrong-family address is a non-match, not an error,
        // so the parse failures are deliberately discarded.
        switch self {
        case .v4:
            do throws(RFC_791.IPv4.Address.Error) {
                return self.contains(try RFC_791.IPv4.Address(binary: Self.byteDomain(address)))
            } catch {
                return false
            }
        case .v6:
            do throws(RFC_4291.IPv6.Address.Error) {
                return self.contains(try RFC_4291.IPv6.Address(binary: Self.byteDomain(address)))
            } catch {
                return false
            }
        }
    }

    /// Bridges ASN.1 octet content (stdlib `UInt8`) into the byte-domain
    /// `Byte` substrate the IPv4/IPv6 address parsers require. The bridge is
    /// contained to this boundary per [API-BYTE-008] (callers bridge at their
    /// own site rather than the address owner adding a `UInt8` forwarder).
    private static func byteDomain(_ octets: some Swift.Sequence<UInt8>) -> [Byte] {
        octets.map { Byte($0) }
    }

    /// Whether the mask is a contiguous run of one-bits followed by
    /// zero-bits, as RFC 4632 (CIDR) style requires.
    ///
    /// -> RFC 4632: the mask/prefix law implemented here (contiguity,
    ///    prefix length, masked containment) transfers to the future
    ///    swift-ietf/swift-rfc-4632 owner for IPv4 and to the RFC 4291
    ///    (IPv6 Standard) side for v6 prefix containment once those
    ///    surfaces exist; this type then delegates and keeps only the
    ///    §4.2.1.10 wire-form split (lead ruling, 2026-07-23).
    public var isCIDRConformant: Bool {
        switch self {
        case .v4(_, let mask):
            return Self.isContiguous(UInt64(Self.hostOrder(mask)) << 32)
        case .v6(_, let mask):
            let segments = Self.segments(of: mask)
            let high = segments[0..<4].reduce(UInt64(0)) { $0 << 16 | UInt64($1) }
            let low = segments[4..<8].reduce(UInt64(0)) { $0 << 16 | UInt64($1) }
            return low == 0 ? Self.isContiguous(high) : high == .max && Self.isContiguous(low)
        }
    }

    /// The CIDR prefix length, or `nil` when the mask is not CIDR
    /// conformant.
    public var prefixLength: Int? {
        guard self.isCIDRConformant else { return nil }
        switch self {
        case .v4(_, let mask):
            return Self.hostOrder(mask).nonzeroBitCount
        case .v6(_, let mask):
            return Self.segments(of: mask).reduce(0) { $0 + $1.nonzeroBitCount }
        }
    }

    /// A contiguous-high-bits word inverts to a contiguous-low-bits value,
    /// which is one less than a power of two.
    private static func isContiguous(_ mask: UInt64) -> Bool {
        let inverted = ~mask
        return (inverted &+ 1) & inverted == 0
    }

    /// The address as a host-order `UInt32` — most significant byte first,
    /// i.e. the first dotted-decimal octet — the representation the mask/prefix
    /// bit analysis requires. Reads the typed octets and bridges each `Byte` to
    /// its `UInt8` carrier at this arithmetic boundary ([API-BYTE-004]); this
    /// avoids `.bigEndian`, which byte-swaps and would invert the bit pattern.
    private static func hostOrder(_ address: RFC_791.IPv4.Address) -> UInt32 {
        let octets = address.octets
        return UInt32(octets.0.underlying) << 24
            | UInt32(octets.1.underlying) << 16
            | UInt32(octets.2.underlying) << 8
            | UInt32(octets.3.underlying)
    }

    private static func segments(of address: RFC_4291.IPv6.Address) -> [UInt16] {
        let segments = address.segments
        return [
            segments.0, segments.1, segments.2, segments.3,
            segments.4, segments.5, segments.6, segments.7,
        ]
    }
}
