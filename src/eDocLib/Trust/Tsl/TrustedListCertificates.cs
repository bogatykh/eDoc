using System.Security.Cryptography.X509Certificates;
using eDocLib.Validation;

namespace eDocLib.Trust.Tsl;

/// <summary>Helpers to combine <see cref="ITrustedListProvider"/> with <see cref="TrustedListCertificateParser"/>.</summary>
internal static class TrustedListCertificates
{
    /// <summary>Downloads TSL XML and returns all embedded certificates (see parser semantics).</summary>
    public static async Task<X509Certificate2Collection> LoadCertificatesAsync(
        ITrustedListProvider provider,
        string territory,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentException.ThrowIfNullOrWhiteSpace(territory);
        await using var stream = await provider.GetTrustedListAsync(territory, cancellationToken).ConfigureAwait(false);
        return TrustedListCertificateParser.ReadCertificates(stream);
    }
}
