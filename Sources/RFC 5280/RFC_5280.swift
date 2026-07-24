// RFC_5280.swift
// Internet X.509 Public Key Infrastructure Certificate and CRL Profile
// https://www.rfc-editor.org/rfc/rfc5280

/// Namespace for RFC 5280: Internet X.509 Public Key Infrastructure
/// Certificate and Certificate Revocation List (CRL) Profile.
///
/// This module owns the certificate *wire and profile law* of RFC 5280:
/// the `TBSCertificate` structure (§4.1), its component types (name, time,
/// validity, algorithm identifier, subject public key info, version, and
/// serial number law), and the wire structure plus criticality semantics of
/// the standard certificate extensions (§4.2).
///
/// It deliberately does not contain certificate *runtime* concerns:
/// signature verification, chain building, trust roots, and policy
/// evaluation are owned by higher layers. All ASN.1 value and encoding law
/// is delegated downward to `ISO_8824` (X.680) and `ISO_8825` (X.690 DER).
public enum RFC_5280 {}
