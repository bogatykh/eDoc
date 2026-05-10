using System.Net.Http;

namespace eDocLib.Revocation.Online;

/// <summary>HTTP GET for a CRL or delta-CRL (DER).</summary>
internal sealed class CrlHttpClient : IDisposable
{
    /// <summary>Stores the HTTP.</summary>
    private readonly HttpClient _http;
    /// <summary>Stores the owned client.</summary>
    private readonly IDisposable? _ownedClient;

    /// <summary>Initializes a new CRL HTTP client instance.</summary>
    public CrlHttpClient(HttpClient? httpClient = null)
    {
        (_http, _ownedClient) = HttpClientOwnership.FromOptional(httpClient);
    }

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

        using var response = await _http.GetAsync(crlUri, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        return await RevocationResponseBodyReader.ReadAsByteArrayWithLimitAsync(
                response.Content,
                maxResponseBytes,
                cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>Releases owned resources.</summary>
    public void Dispose()
    {
        _ownedClient?.Dispose();
    }
}
