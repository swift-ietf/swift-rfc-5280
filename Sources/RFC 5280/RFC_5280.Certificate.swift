// RFC_5280.Certificate.swift
// RFC 5280 §4.1 — Basic Certificate Fields
// https://www.rfc-editor.org/rfc/rfc5280#section-4.1

extension RFC_5280 {
    /// Nest for certificate-scoped profile law (RFC 5280 §4.1).
    ///
    /// The outer `Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
    /// signatureValue }` runtime type is owned by the certificate-runtime layer;
    /// this nest hosts the profile-law members ``RFC_5280/Certificate/Version``
    /// (§4.1.2.1) and ``RFC_5280/Certificate/SerialNumber`` (§4.1.2.2), and the
    /// to-be-signed structure itself lives at ``RFC_5280/TBSCertificate``.
    public enum Certificate {}
}
