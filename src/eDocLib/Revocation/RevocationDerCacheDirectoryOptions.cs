namespace eDocLib.Revocation;

/// <summary>Options for <see cref="DirectoryRevocationDerCache"/> entry lifetime.</summary>
public sealed record RevocationDerCacheDirectoryOptions
{
    /// <summary>
    /// When set, a cache file whose last write time is older than this (UTC) is treated as a miss.
    /// </summary>
    public TimeSpan? MaxEntryAge { get; init; }

    /// <summary>
    /// When <c>true</c> (default) and <see cref="MaxEntryAge"/> is set, an expired file is deleted on read.
    /// </summary>
    public bool DeleteExpiredFileOnRead { get; init; } = true;

    /// <summary>
    /// When set, the number of <c>*.der</c> files in the cache directory is kept at or below this value by deleting
    /// the oldest files (by last write time UTC, then path) after each <see cref="DirectoryRevocationDerCache.SetAsync"/>
    /// and from <see cref="DirectoryRevocationDerCache.PurgeExpiredEntriesAsync"/>.
    /// </summary>
    public int? MaxEntryCount { get; init; }

    /// <summary>
    /// When set, the combined size of all <c>*.der</c> files is kept at or below this byte total using the same
    /// eviction order as <see cref="MaxEntryCount"/>.
    /// </summary>
    public long? MaxTotalBytes { get; init; }
}
