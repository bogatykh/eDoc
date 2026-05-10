namespace eDocLib.Timestamp;

/// <summary>
/// Obtain an RFC 3161 time-stamp token for a message imprint (e.g. SHA-256 of raw <c>SignatureValue</c> octets for XAdES-T).
/// </summary>
public interface ITimestampProvider
{
    /// <param name="messageImprint">Hash octets (e.g. SHA-256 of <c>SignatureValue</c> or signed attributes per profile).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<byte[]> GetTimestampAsync(ReadOnlyMemory<byte> messageImprint, CancellationToken cancellationToken = default);
}
