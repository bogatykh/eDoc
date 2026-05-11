namespace eDocLib.Trust.Tsl;

/// <summary>
/// Placeholder <see cref="ITrustedListProvider"/> for applications that do not load TSL yet.
/// Returns an empty stream; hosts should replace this with a real implementation for V-05.
/// </summary>
public sealed class NullTrustedListProvider : ITrustedListProvider
{
    /// <inheritdoc />
    public Task<Stream> GetTrustedListAsync(string territory, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(territory);
        return Task.FromResult<Stream>(new MemoryStream(Array.Empty<byte>()));
    }
}
