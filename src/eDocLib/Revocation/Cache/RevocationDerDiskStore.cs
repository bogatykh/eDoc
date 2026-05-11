using eDocLib.Revocation;

namespace eDocLib.Revocation.Cache;

/// <summary>
/// Named disk-backed cache for OCSP and CRL DER blobs (checklist EP-31 — local DER store / CRL manager role).
/// Delegates to <see cref="DirectoryRevocationDerCache"/>; use when wiring <see cref="eDocLib.Validation.SignatureTrustPolicy.RevocationDerCache"/>.
/// </summary>
internal sealed class RevocationDerDiskStore : IRevocationDerCache
{
    private readonly DirectoryRevocationDerCache _inner;

    /// <summary>Initializes a new revocation DER disk store instance.</summary>
    /// <inheritdoc cref="DirectoryRevocationDerCache.DirectoryRevocationDerCache(string, RevocationDerCacheDirectoryOptions?)" />
    public RevocationDerDiskStore(string directory, RevocationDerCacheDirectoryOptions? options = null)
    {
        _inner = new DirectoryRevocationDerCache(directory, options);
    }

    /// <inheritdoc cref="DirectoryRevocationDerCache.DirectoryPath" />
    public string DirectoryPath => _inner.DirectoryPath;

    /// <inheritdoc cref="DirectoryRevocationDerCache.PurgeExpiredEntriesAsync(CancellationToken)" />
    public Task PurgeExpiredEntriesAsync(CancellationToken cancellationToken = default) =>
        _inner.PurgeExpiredEntriesAsync(cancellationToken);

    /// <inheritdoc />
    public ValueTask<byte[]?> TryGetAsync(string key, CancellationToken cancellationToken = default) =>
        _inner.TryGetAsync(key, cancellationToken);

    /// <inheritdoc />
    public Task SetAsync(string key, ReadOnlyMemory<byte> der, CancellationToken cancellationToken = default) =>
        _inner.SetAsync(key, der, cancellationToken);
}
