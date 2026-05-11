using System.Net.Http;
using eDocLib;

namespace eDocLib.Revocation.Online;

/// <summary>HTTP GET for a CRL or delta-CRL (DER).</summary>
internal sealed class CrlHttpClient : IDisposable
{
    private readonly HttpClientOwnership.HttpClientLease _http;

    /// <summary>Initializes a new CRL HTTP client instance.</summary>
    public CrlHttpClient(HttpClient? httpClient = null) =>
        _http = new HttpClientOwnership.HttpClientLease(httpClient);

    /// <summary>Downloads async.</summary>
    public async Task<byte[]> DownloadAsync(
        Uri crlUri,
        int maxResponseBytes = RevocationFetchLimits.DefaultMaxResponseBytes,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(crlUri);
        if (maxResponseBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxResponseBytes));
        }

        using var response = await _http.Client.GetAsync(crlUri, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        return await RevocationResponseBodyReader.ReadAsByteArrayWithLimitAsync(
                response.Content,
                maxResponseBytes,
                cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>Releases owned resources.</summary>
    public void Dispose() => _http.Dispose();
}
