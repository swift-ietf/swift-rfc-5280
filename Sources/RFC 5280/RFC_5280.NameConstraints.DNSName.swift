// RFC_5280.NameConstraints.DNSName.swift
// RFC 5280 §4.2.1.10 — Name Constraints: dNSName matching law
// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.10

public import Domain_Standard

extension RFC_5280.NameConstraints {
    /// The §4.2.1.10 constraint-matching law for the `dNSName` name form.
    ///
    /// "DNS name restrictions are expressed as host.example.com. Any DNS
    /// name that can be constructed by simply adding zero or more labels to
    /// the left-hand side of the name satisfies the name constraint. For
    /// example, www.host.example.com would satisfy the constraint but
    /// host1.example.com would not." (§4.2.1.10)
    ///
    /// Matching is therefore equality or a whole-label subdomain relation.
    /// Domain syntax and comparison law (label decomposition, ASCII
    /// case-insensitivity per RFC 4343) belong to ``Domain_Standard/Domain``;
    /// this type owns only the profile rule. `dNSName` values MUST use the
    /// RFC 1034/1123 preferred name syntax (see ``RFC_5280/GeneralName``),
    /// so a wire value outside that syntax satisfies no constraint.
    public enum DNSName {}
}

extension RFC_5280.NameConstraints.DNSName {
    /// Whether `name` satisfies the dNSName `constraint` under §4.2.1.10:
    /// `name` can be constructed by adding zero or more labels to the left
    /// of `constraint`.
    public static func satisfies(_ name: Domain, constraint: Domain) -> Bool {
        // Compare via the always-present RFC 1123 member: its `==` is ASCII
        // case-insensitive (RFC 4343), whereas `Domain`'s synthesized `==`
        // also compares the optional RFC 1035 member, which an uppercase host
        // fails to populate — making whole-`Domain` equality case-sensitive.
        name.rfc1123 == constraint.rfc1123 || name.isSubdomain(of: constraint)
    }

    /// The wire-value convenience over ``satisfies(_:constraint:)``.
    ///
    /// An empty constraint is satisfied by every name (zero or more labels
    /// added to the empty name). A name or non-empty constraint that is not
    /// a valid RFC 1123 domain satisfies nothing: the profile requires the
    /// preferred name syntax of both.
    public static func satisfies(_ name: some StringProtocol, constraint: some StringProtocol) -> Bool {
        guard !constraint.isEmpty else { return true }
        guard
            let name = Self.domain(name),
            let constraint = Self.domain(constraint)
        else { return false }
        return Self.satisfies(name, constraint: constraint)
    }

    /// Invalid domain syntax is a non-match, not an error, so the parse
    /// failure is deliberately discarded.
    private static func domain(_ string: some StringProtocol) -> Domain? {
        do throws(Domain.Error) {
            return try Domain(string)
        } catch {
            return nil
        }
    }
}
