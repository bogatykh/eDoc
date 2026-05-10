namespace eDocLib.Revocation;

/// <summary>
/// Optional disk or custom cache for raw OCSP/CRL DER used by application-controlled online revocation.
/// Keys are opaque strings; <see cref="DirectoryRevocationDerCache"/> hashes them for file names and can apply
/// <see cref="RevocationDerCacheDirectoryOptions"/> (max age, optional entry count / total size caps, purge).
/// </summary>
public interface IRevocationDerCache
{
    /// <summary>Returns cached DER or <c>null</c> if missing.</summary>
    ValueTask<byte[]?> TryGetAsync(string key, CancellationToken cancellationToken = default);

    /// <summary>Persists DER under <paramref name="key"/> (overwrites).</summary>
    Task SetAsync(string key, ReadOnlyMemory<byte> der, CancellationToken cancellationToken = default);
}
