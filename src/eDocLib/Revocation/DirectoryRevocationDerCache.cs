using System.Linq;

namespace eDocLib.Revocation;

/// <summary>
/// Stores revocation DER as files named SHA-256(hex UTF-8 key) + <c>.der</c>.
/// <see cref="SetAsync"/> writes to a <c>*.tmp</c> file and atomically replaces the target (<see cref="File.Move(string,string,bool)"/>),
/// so readers either see the previous file or the full new payload, not a partial write.
/// Optional <see cref="RevocationDerCacheDirectoryOptions.MaxEntryCount"/> / <see cref="RevocationDerCacheDirectoryOptions.MaxTotalBytes"/>
/// evict oldest files (by last write time UTC, then path) after writes and from <see cref="PurgeExpiredEntriesAsync"/>.
/// </summary>
public sealed class DirectoryRevocationDerCache : IRevocationDerCache
{
    /// <summary>Stores the directory.</summary>
    private readonly string _directory;
    /// <summary>Stores the options.</summary>
    private readonly RevocationDerCacheDirectoryOptions? _options;

    /// <summary>Initializes a new directory revocation DER cache instance.</summary>
    /// <param name="directory">Directory used to store cached <c>*.der</c> files.</param>
    /// <param name="options">Optional expiration and capacity limits.</param>
    public DirectoryRevocationDerCache(string directory, RevocationDerCacheDirectoryOptions? options = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        _directory = directory.Trim();
        _options = options;
        if (_options?.MaxEntryAge is { } maxAge && maxAge < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "MaxEntryAge must not be negative.");
        }

        if (_options?.MaxEntryCount is { } maxCount && maxCount < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "MaxEntryCount must be at least 1 when set.");
        }

        if (_options?.MaxTotalBytes is { } maxBytes && maxBytes < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "MaxTotalBytes must be at least 1 when set.");
        }
    }

    /// <summary>Directory used to store cached DER files.</summary>
    public string DirectoryPath => _directory;

    /// <summary>Attempts to get async.</summary>
    /// <inheritdoc />
    public async ValueTask<byte[]?> TryGetAsync(string key, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        var path = GetPathForKey(key);
        if (!File.Exists(path))
        {
            return null;
        }

        if (IsExpired(path))
        {
            if (_options is { DeleteExpiredFileOnRead: true })
            {
                IoSafe.TryDeleteFile(path);
            }

            return null;
        }

        return await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Sets async.</summary>
    /// <inheritdoc />
    public async Task SetAsync(string key, ReadOnlyMemory<byte> der, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        Directory.CreateDirectory(_directory);
        var path = GetPathForKey(key);
        var tmp = path + ".tmp";
        await File.WriteAllBytesAsync(tmp, der.ToArray(), cancellationToken).ConfigureAwait(false);
        File.Move(tmp, path, overwrite: true);
        EnforceCapacityLimits();
    }

    /// <summary>
    /// Deletes <c>*.der</c> files under <see cref="DirectoryPath"/> that exceed <see cref="RevocationDerCacheDirectoryOptions.MaxEntryAge"/>.
    /// When <see cref="RevocationDerCacheDirectoryOptions.MaxEntryCount"/> or <see cref="RevocationDerCacheDirectoryOptions.MaxTotalBytes"/>
    /// is set, also evicts oldest entries until within those limits.
    /// </summary>
    public Task PurgeExpiredEntriesAsync(CancellationToken cancellationToken = default)
    {
        if (!Directory.Exists(_directory))
        {
            return Task.CompletedTask;
        }

        if (_options?.MaxEntryAge is { } maxAge)
        {
            var now = DateTime.UtcNow;
            foreach (var file in Directory.EnumerateFiles(_directory, "*.der", SearchOption.TopDirectoryOnly))
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    if (now - File.GetLastWriteTimeUtc(file) > maxAge)
                    {
                        File.Delete(file);
                    }
                }
                catch (IOException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
            }
        }

        cancellationToken.ThrowIfCancellationRequested();
        EnforceCapacityLimits();
        return Task.CompletedTask;
    }

    /// <summary>Returns whether expired.</summary>
    private bool IsExpired(string path)
    {
        if (_options?.MaxEntryAge is not { } max)
        {
            return false;
        }

        return DateTime.UtcNow - File.GetLastWriteTimeUtc(path) > max;
    }

    /// <summary>Enforces capacity limits.</summary>
    private void EnforceCapacityLimits()
    {
        if (_options is not { } o)
        {
            return;
        }

        if (o.MaxEntryCount is null && o.MaxTotalBytes is null)
        {
            return;
        }

        if (!Directory.Exists(_directory))
        {
            return;
        }

        var maxCount = o.MaxEntryCount;
        var maxBytes = o.MaxTotalBytes;

        while (true)
        {
            List<FileInfo> entries;
            try
            {
                entries = Directory
                    .EnumerateFiles(_directory, "*.der", SearchOption.TopDirectoryOnly)
                    .Select(p => new FileInfo(p))
                    .OrderBy(f => f.LastWriteTimeUtc)
                    .ThenBy(f => f.FullName, StringComparer.Ordinal)
                    .ToList();
            }
            catch (IOException)
            {
                return;
            }
            catch (UnauthorizedAccessException)
            {
                return;
            }

            var total = entries.Sum(f => f.Length);
            var overCount = maxCount is { } mc && entries.Count > mc;
            var overBytes = maxBytes is { } mb && total > mb;
            if (!overCount && !overBytes)
            {
                return;
            }

            if (entries.Count == 0)
            {
                return;
            }

            var victim = entries[0];
            if (!IoSafe.TryDeleteFile(victim.FullName))
            {
                return;
            }
        }
    }

    /// <summary>Gets path for key.</summary>
    private string GetPathForKey(string key)
    {
        var hash = CacheFileNames.Sha256HexKey(key);
        return Path.Combine(_directory, hash + ".der");
    }
}
