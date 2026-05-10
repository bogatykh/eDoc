using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using eDocLib.Revocation;
using eDocLib.Revocation.Cache;

namespace eDocLib.Revocation.Online;

/// <summary>Downloads OCSP and CRL DER via <see cref="HttpClient"/> using certificate AIA and CDP extensions; optionally loads a delta CRL from the base CRL’s Freshest CRL extension.</summary>
internal static class CertificateRevocationMaterialFetcher
{
    /// <summary>
    /// POSTs to the first HTTP(S) OCSP URI from AIA (if any). Downloads from the first reachable HTTP(S) CRL URI (tries CDP entries in order).
    /// Does not validate OCSP or CRL contents; failures on OCSP propagate; CRL failures try the next URI.
    /// </summary>
    /// <param name="endEntity">Certificate whose revocation material is fetched.</param>
    /// <param name="issuer">Issuer certificate used to build the OCSP request cache key and request body.</param>
    /// <param name="http">HTTP client used for OCSP and CRL requests.</param>
    /// <param name="maxResponseBytes">Maximum bytes read per HTTP response body (OCSP and each CRL attempt).</param>
    /// <param name="rejectLiteralPrivateAndLoopbackHosts">When <c>true</c>, URIs whose host is a literal loopback or private address are rejected before any HTTP request.</param>
    /// <param name="responseCache">When non-null, successful OCSP/CRL DER is stored and reused (see <see cref="RevocationDerCacheKeys"/>).</param>
    /// <param name="fetchDeltaCrlViaFreshestCdp">
    /// When <c>true</c>, after a successful base CRL download from CDP, attempts to download a delta CRL from HTTP(S) URIs in the base CRL’s Freshest CRL extension (RFC 5280).
    /// Missing extension or unreachable URIs do not fail the overall fetch.
    /// </param>
    /// <param name="cancellationToken">Cancellation token for HTTP and cache operations.</param>
    public static async Task<RevocationMaterialFetchResult> FetchAsync(
        X509Certificate2 endEntity,
        X509Certificate2 issuer,
        HttpClient http,
        int maxResponseBytes = RevocationFetchLimits.DefaultMaxResponseBytes,
        bool rejectLiteralPrivateAndLoopbackHosts = false,
        IRevocationDerCache? responseCache = null,
        bool fetchDeltaCrlViaFreshestCdp = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(endEntity);
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(http);
        if (maxResponseBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxResponseBytes));
        }

        var ocsp = new List<byte[]>();
        if (X509RevocationUriDiscovery.TryGetOcspHttpUri(endEntity, out var ocspUri) && ocspUri is not null)
        {
            if (!RevocationFetchUriPolicy.IsAllowed(ocspUri, rejectLiteralPrivateAndLoopbackHosts, out var ocspUriErr))
            {
                throw new InvalidOperationException(ocspUriErr);
            }

            var ocspKey = RevocationDerCacheKeys.Ocsp(endEntity, issuer, ocspUri);
            var der = await GetOrFetchCachedDerAsync(
                    responseCache,
                    ocspKey,
                    () => FetchOcspDerUncachedAsync(ocspUri, endEntity, issuer, http, maxResponseBytes, cancellationToken),
                    cancellationToken)
                .ConfigureAwait(false);
            ocsp.Add(der);
        }

        var crls = await FetchCrlListAsync(
                endEntity,
                http,
                maxResponseBytes,
                rejectLiteralPrivateAndLoopbackHosts,
                responseCache,
                fetchDeltaCrlViaFreshestCdp,
                cancellationToken)
            .ConfigureAwait(false);

        return new RevocationMaterialFetchResult(ocsp, crls);
    }

    /// <summary>Gets or fetch cached DER async.</summary>
    private static async Task<byte[]> GetOrFetchCachedDerAsync(
        IRevocationDerCache? cache,
        string cacheKey,
        Func<Task<byte[]>> fetchUncached,
        CancellationToken cancellationToken)
    {
        if (cache is null)
        {
            return await fetchUncached().ConfigureAwait(false);
        }

        var cached = await cache.TryGetAsync(cacheKey, cancellationToken).ConfigureAwait(false);
        if (cached is { Length: > 0 })
        {
            return cached;
        }

        var der = await fetchUncached().ConfigureAwait(false);
        await cache.SetAsync(cacheKey, der, cancellationToken).ConfigureAwait(false);
        return der;
    }

    /// <summary>Fetches OCSP DER uncached async.</summary>
    private static async Task<byte[]> FetchOcspDerUncachedAsync(
        Uri ocspUri,
        X509Certificate2 endEntity,
        X509Certificate2 issuer,
        HttpClient http,
        int maxResponseBytes,
        CancellationToken cancellationToken)
    {
        using var ocspClient = new OcspHttpClient(http);
        return await ocspClient
            .QueryAsync(ocspUri, endEntity, issuer, maxResponseBytes, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>Fetches CRL list async.</summary>
    private static async Task<List<byte[]>> FetchCrlListAsync(
        X509Certificate2 endEntity,
        HttpClient http,
        int maxResponseBytes,
        bool rejectLiteralPrivateAndLoopbackHosts,
        IRevocationDerCache? responseCache,
        bool fetchDeltaCrlViaFreshestCdp,
        CancellationToken cancellationToken)
    {
        var crls = new List<byte[]>();
        foreach (var crlUri in X509RevocationUriDiscovery.GetCrlHttpUris(endEntity))
        {
            if (!RevocationFetchUriPolicy.IsAllowed(crlUri, rejectLiteralPrivateAndLoopbackHosts, out var crlUriErr))
            {
                throw new InvalidOperationException(crlUriErr);
            }

            try
            {
                var crlKey = RevocationDerCacheKeys.Crl(crlUri);
                var der = await GetOrFetchCachedDerAsync(
                        responseCache,
                        crlKey,
                        () => FetchCrlDerUncachedAsync(crlUri, http, maxResponseBytes, cancellationToken),
                        cancellationToken)
                    .ConfigureAwait(false);
                crls.Add(der);
                if (fetchDeltaCrlViaFreshestCdp)
                {
                    foreach (var deltaUri in X509RevocationUriDiscovery.GetFreshestCrlHttpUris(der))
                    {
                        if (!RevocationFetchUriPolicy.IsAllowed(deltaUri, rejectLiteralPrivateAndLoopbackHosts, out var deltaUriErr))
                        {
                            throw new InvalidOperationException(deltaUriErr);
                        }

                        try
                        {
                            var deltaKey = RevocationDerCacheKeys.Crl(deltaUri);
                            var deltaDer = await GetOrFetchCachedDerAsync(
                                    responseCache,
                                    deltaKey,
                                    () => FetchCrlDerUncachedAsync(deltaUri, http, maxResponseBytes, cancellationToken),
                                    cancellationToken)
                                .ConfigureAwait(false);
                            crls.Add(deltaDer);
                            break;
                        }
                        catch (HttpRequestException)
                        {
                            // try next freshest distribution point
                        }
                    }
                }

                break;
            }
            catch (HttpRequestException)
            {
                // try next distribution point
            }
        }

        return crls;
    }

    /// <summary>Fetches CRL DER uncached async.</summary>
    private static async Task<byte[]> FetchCrlDerUncachedAsync(
        Uri crlUri,
        HttpClient http,
        int maxResponseBytes,
        CancellationToken cancellationToken)
    {
        using var crlClient = new CrlHttpClient(http);
        return await crlClient.DownloadAsync(crlUri, maxResponseBytes, cancellationToken).ConfigureAwait(false);
    }
}
