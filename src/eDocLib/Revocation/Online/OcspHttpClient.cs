using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;

using eDocLib.Revocation.Protocols.Ocsp;

namespace eDocLib.Revocation.Online;

/// <summary>
/// Application-facing OCSP HTTP client: POSTs an OCSP request (RFC 6960) and returns the raw response DER (checklist EP-31 — OCSP HTTP transport).
/// Cryptographic validation of the OCSP response is performed by <see cref="eDocLib.Revocation.Verify.EmbeddedRevocationVerifier"/> / <see cref="eDocLib.Revocation.Verify.OnlineRevocationVerifier"/>.
/// </summary>
internal sealed class OcspHttpClient : IDisposable
{
    /// <summary>Stores the HTTP.</summary>
    private readonly HttpClient _http;
    /// <summary>Stores the owned client.</summary>
    private readonly IDisposable? _ownedClient;

    /// <summary>Initializes a new OCSP HTTP client instance.</summary>
    public OcspHttpClient(HttpClient? httpClient = null)
    {
        (_http, _ownedClient) = HttpClientOwnership.FromOptional(httpClient);
    }

    /// <summary>
    /// Sends <see cref="OcspRequestBuilder.BuildDer"/> to <paramref name="ocspResponder"/> and returns the response body.
    /// Does not validate the OCSP response cryptographically.
    /// </summary>
    public async Task<byte[]> QueryAsync(
        Uri ocspResponder,
        X509Certificate2 subject,
        X509Certificate2 issuer,
        int maxResponseBytes = RevocationFetchLimits.DefaultMaxResponseBytes,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ocspResponder);
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(issuer);
        if (maxResponseBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxResponseBytes));
        }

        var reqDer = OcspRequestBuilder.BuildDer(subject, issuer);
        using var content = new ByteArrayContent(reqDer);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/ocsp-request");
        using var request = new HttpRequestMessage(HttpMethod.Post, ocspResponder) { Content = content };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/ocsp-response"));

        using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
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
