namespace eDocLib.Revocation;

/// <summary>Kind of revocation DER artifact reported in <see cref="RevocationArtifactOutcome"/>.</summary>
public enum RevocationArtifactKind
{
    /// <summary>Online Certificate Status Protocol response.</summary>
    Ocsp,

    /// <summary>Certificate revocation list.</summary>
    Crl,
}
