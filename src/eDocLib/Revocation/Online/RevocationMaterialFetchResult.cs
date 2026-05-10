namespace eDocLib.Revocation.Online;

/// <summary>Raw revocation artifacts downloaded for LT-style embedding (not cryptographically verified here).</summary>
internal sealed record RevocationMaterialFetchResult(
    IReadOnlyList<byte[]> OcspResponses,
    IReadOnlyList<byte[]> Crls);
