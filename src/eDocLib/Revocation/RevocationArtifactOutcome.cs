namespace eDocLib.Revocation;

/// <summary>
/// Outcome for one non-empty OCSP or CRL DER blob (embedded <c>RevocationValues</c> or application-fetched material).
/// </summary>
/// <param name="Kind">Whether this blob was parsed as OCSP or CRL.</param>
/// <param name="Ordinal">Zero-based index among non-empty blobs of this kind in the corresponding input list.</param>
/// <param name="Success"><c>true</c> when cryptographic verification of this blob succeeded.</param>
/// <param name="Detail">Human-readable failure detail when <paramref name="Success"/> is <c>false</c>; otherwise <c>null</c>.</param>
public sealed record RevocationArtifactOutcome(
    RevocationArtifactKind Kind,
    int Ordinal,
    bool Success,
    string? Detail);
