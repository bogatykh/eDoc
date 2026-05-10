namespace eDocLib.Trust.Tsl;

/// <summary>
/// Abstraction for obtaining EU / national TSL XML bytes; hosts feed streams into the validation stack (e.g. build a <see cref="eDocLib.Validation.TrustedListServiceIndex"/> for <see cref="eDocLib.Validation.SignatureTrustPolicy"/>).
/// </summary>
public interface ITrustedListProvider
{
    /// <summary>
    /// Returns a new readable stream of TSL XML. Caller disposes the stream.
    /// Territory semantics are implementation-defined; see <see cref="HttpTslTrustedListProvider"/>.
    /// </summary>
    Task<Stream> GetTrustedListAsync(string territory, CancellationToken cancellationToken = default);
}
