// RFC_5280.NameConstraints.URI.swift
// RFC 5280 §4.2.1.10 — Name Constraints: uniformResourceIdentifier matching law
// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.10

// Domain is used only in the private helper below, never in a public
// signature, so this import is internal (not `public import`).
import Domain_Standard

extension RFC_5280.NameConstraints {
    /// The §4.2.1.10 constraint-matching law for the
    /// `uniformResourceIdentifier` name form.
    ///
    /// "For URIs, the constraint applies to the host part of the name. The
    /// constraint MUST be specified as a fully qualified domain name and MAY
    /// specify a host or a domain. Examples would be 'host.example.com' and
    /// '.example.com'. When the constraint begins with a period, it MAY be
    /// expanded with one or more labels. That is, the constraint
    /// '.example.com' is satisfied by both host.example.com and
    /// my.host.example.com. However, the constraint '.example.com' is not
    /// satisfied by 'example.com'. When the constraint does not begin with
    /// a period, it specifies a host." (§4.2.1.10)
    ///
    /// The law here takes the already-extracted host: parsing a URI into
    /// components is RFC 3986 law and is owned by that RFC's module, not
    /// duplicated in this profile. Domain syntax and comparison law belong
    /// to ``Domain_Standard/Domain``. Constraints are domain names, so a
    /// URI whose authority is an IP address or is absent never satisfies a
    /// URI constraint.
    public enum URI {}
}

extension RFC_5280.NameConstraints.URI {
    /// Whether a URI's `host` satisfies the URI `constraint` under
    /// §4.2.1.10: a leading-period constraint matches any host expanded
    /// from it by one or more labels; otherwise the constraint names
    /// exactly one host.
    public static func satisfies(host: some StringProtocol, constraint: some StringProtocol) -> Bool {
        guard let host = Self.domain(host) else { return false }
        if constraint.first == "." {
            guard let constraint = Self.domain(constraint.dropFirst()) else { return false }
            // Expanded by one or more labels: the strict subdomain relation.
            return host.isSubdomain(of: constraint)
        }
        guard let constraint = Self.domain(constraint) else { return false }
        // Compare via the RFC 1123 member for ASCII case-insensitive equality
        // (RFC 4343); whole-`Domain` `==` is case-sensitive via its optional
        // RFC 1035 member (see ``RFC_5280/NameConstraints/DNSName``).
        return host.rfc1123 == constraint.rfc1123
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
