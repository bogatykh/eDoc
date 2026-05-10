namespace eDocLib.Revocation.Protocols.Ocsp;

/// <summary>One <c>SingleResponse</c> from a Basic OCSP response (no crypto validation).</summary>
internal sealed record OcspSingleResponseEntry(
    byte[] CertificateSerialNumber,
    OcspCertificateStatusKind Status,
    DateTimeOffset? RevokedAt);
