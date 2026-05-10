namespace eDocLib.Timestamp;

/// <summary>
/// Returns a fixed DER time-stamp token (e.g. for tests or offline demos). Does not validate the imprint.
/// </summary>
internal sealed class PrecomputedTimestampTokenProvider : ITimestampProvider
{
    /// <summary>Stores the token.</summary>
    private readonly byte[] _token;

    /// <summary>Initializes a new precomputed timestamp token provider instance.</summary>
    public PrecomputedTimestampTokenProvider(byte[] timeStampTokenDer)
    {
        ArgumentNullException.ThrowIfNull(timeStampTokenDer);
        _token = (byte[])timeStampTokenDer.Clone();
    }

    /// <summary>Gets timestamp async.</summary>
    public Task<byte[]> GetTimestampAsync(ReadOnlyMemory<byte> messageImprint, CancellationToken cancellationToken = default) =>
        Task.FromResult((byte[])_token.Clone());
}
