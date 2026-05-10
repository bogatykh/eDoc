namespace eDocLib.Validation;

/// <summary>
/// Whether archive RFC 3161 tokens are checked against the digest input produced by the same rule as
/// <see cref="M:eDocLib.Asic.Xades.XadesBesSigner.ComputeDefaultArchiveTimestampImprintSha256(eDocLib.Asic.Container.AsicSignature)"/>.
/// </summary>
public enum ArchiveTimestampImprintPolicy
{
    /// <summary>Do not verify message imprint vs reconstructed signature XML.</summary>
    Ignore = 0,

    /// <summary>
    /// When at least one <c>xades:ArchiveTimeStamp</c> is present, require each token’s SHA-256 message imprint to match the default
    /// archive digest input (see <see cref="M:eDocLib.Asic.Xades.XadesBesSigner.ComputeDefaultArchiveTimestampImprintSha256(eDocLib.Asic.Container.AsicSignature)"/>); chaining order matches append order.
    /// </summary>
    RequireWhenPresent = 1,
}
