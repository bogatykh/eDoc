using System.Threading;
using eDocLib;

namespace eDocLib.Trust.Tsl;

/// <summary>
/// Wraps another <see cref="ITrustedListProvider"/> and stores successful TSL XML on disk.
/// Cache key is SHA-256 of the territory string (same semantics as the inner provider).
/// </summary>
public sealed class CachingTslTrustedListProvider : ITrustedListProvider
{
    private readonly ITrustedListProvider _inner;
    private readonly string _cacheDirectory;

    /// <summary>Initializes a new caching TSL trusted list provider instance.</summary>
    /// <param name="inner">Network or other source.</param>
    /// <param name="cacheDirectory">Directory created if missing; one file per territory key.</param>
    /// <param name="maxAge">
    /// Maximum age of a cached file before re-download; <c>null</c> defaults to 24 hours.
    /// <see cref="Timeout.InfiniteTimeSpan"/> never expires. Non-positive finite values keep entries always stale (always refetch).
    /// </param>
    public CachingTslTrustedListProvider(
        ITrustedListProvider inner,
        string cacheDirectory,
        TimeSpan? maxAge = null)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentException.ThrowIfNullOrWhiteSpace(cacheDirectory);
        _inner = inner;
        _cacheDirectory = cacheDirectory.Trim();
        MaxAge = maxAge ?? TimeSpan.FromHours(24);
    }

    /// <summary>Maximum cache age before refetch.</summary>
    public TimeSpan MaxAge { get; }

    /// <inheritdoc />
    public async Task<Stream> GetTrustedListAsync(string territory, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(territory);
        Directory.CreateDirectory(_cacheDirectory);
        var path = GetCacheFilePath(territory);

        if (File.Exists(path) && IsCacheEntryFresh(path))
        {
            return File.OpenRead(path);
        }

        await using var remote = await _inner.GetTrustedListAsync(territory, cancellationToken).ConfigureAwait(false);
        using var buffer = new MemoryStream();
        await remote.CopyToAsync(buffer, cancellationToken).ConfigureAwait(false);
        var bytes = buffer.ToArray();

        await IoSafe.WriteAllBytesAtomicAsync(path, bytes, cancellationToken).ConfigureAwait(false);

        return new MemoryStream(bytes, writable: false);
    }

    private bool IsCacheEntryFresh(string path)
    {
        if (MaxAge == Timeout.InfiniteTimeSpan)
        {
            return true;
        }

        if (MaxAge <= TimeSpan.Zero)
        {
            return false;
        }

        var age = DateTime.UtcNow - File.GetLastWriteTimeUtc(path);
        return age <= MaxAge;
    }

    private string GetCacheFilePath(string territory)
    {
        var hash = CacheFileNames.Sha256HexKey(territory.Trim());
        return Path.Combine(_cacheDirectory, hash + ".tsl.xml");
    }
}
