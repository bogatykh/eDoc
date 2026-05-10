using System.Net.Http;
using System.Security.Cryptography.X509Certificates;

namespace eDocLib.Revocation.Online;

/// <summary>Internal seam for substituting revocation HTTP fetch in tests (ISP); default wraps <see cref="CertificateRevocationMaterialFetcher"/>.</summary>
internal interface IRevocationMaterialFetcher
{
    Task<RevocationMaterialFetchResult> FetchAsync(
        X509Certificate2 endEntity,
        X509Certificate2 issuer,
        HttpClient http,
        int maxResponseBytes,
        bool rejectLiteralPrivateAndLoopbackHosts,
        IRevocationDerCache? responseCache,
        bool fetchDeltaCrlViaFreshestCdp,
        CancellationToken cancellationToken);
}

/// <summary>Fetches revocation material with the default HTTP implementation.</summary>
internal sealed class DefaultRevocationMaterialFetcher : IRevocationMaterialFetcher
{
    /// <summary>Fetches async.</summary>
    public Task<RevocationMaterialFetchResult> FetchAsync(
        X509Certificate2 endEntity,
        X509Certificate2 issuer,
        HttpClient http,
        int maxResponseBytes,
        bool rejectLiteralPrivateAndLoopbackHosts,
        IRevocationDerCache? responseCache,
        bool fetchDeltaCrlViaFreshestCdp,
        CancellationToken cancellationToken) =>
        CertificateRevocationMaterialFetcher.FetchAsync(
            endEntity,
            issuer,
            http,
            maxResponseBytes,
            rejectLiteralPrivateAndLoopbackHosts,
            responseCache,
            fetchDeltaCrlViaFreshestCdp,
            cancellationToken);
}

/// <summary>Lazily constructed singleton used when callers omit a custom <see cref="IRevocationMaterialFetcher"/>.</summary>
internal static class RevocationMaterialFetcherDefaults
{
    /// <summary>Shared fetcher with library defaults (timeouts, response caps).</summary>
    public static IRevocationMaterialFetcher Instance { get; } = new DefaultRevocationMaterialFetcher();
}
