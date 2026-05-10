namespace eDocLib.Revocation.Protocols.Ocsp;

/// <summary>Summary of an OCSP single-response certificate status (good, revoked, or unknown).</summary>
internal enum OcspCertificateStatusKind
{
    /// <summary>Represents the good value.</summary>
    Good,
    /// <summary>Represents the revoked value.</summary>
    Revoked,
    /// <summary>Represents the unknown value.</summary>
    Unknown,
}
