using eDocLib.Validation;

namespace eDocLib.Trust.Tsl;

/// <summary>
/// EP-40: orchestrates <see cref="ITrustedListProvider"/> (HTTP or host implementation) to fetch TSL XML and return a parsed
/// <see cref="TrustedListLoadResult"/> in one step.
/// Does not schedule refreshes; federation timing remains host-defined.
/// </summary>
public sealed class TrustedListManager
{
    /// <summary>Stores the provider.</summary>
    private readonly ITrustedListProvider _provider;

    /// <summary>Initializes a new trusted list manager instance.</summary>
    /// <param name="provider">Provider used to retrieve trusted-list XML streams.</param>
    public TrustedListManager(ITrustedListProvider provider)
    {
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
    }

    /// <summary>
    /// Downloads TSL XML for <paramref name="territory"/> (semantics depend on <see cref="ITrustedListProvider"/>),
    /// then validates and parses it.
    /// </summary>
    public async Task<(TrustedListLoadResult? Result, string? Error)> LoadAsync(
        string territory,
        bool verifyXmlSignature,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(territory);
        await using var stream = await _provider.GetTrustedListAsync(territory, cancellationToken).ConfigureAwait(false);
        var ok = TrustedListValidator.TryValidate(stream, verifyXmlSignature, out var result, out var error);
        return ok ? (result, null) : (null, error);
    }
}
