using System.Net.Http.Headers;
using System.Security.Cryptography;
using eDocLib;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Tsp;

namespace eDocLib.Timestamp;

/// <summary>
/// RFC 3161 client: POST <c>application/timestamp-query</c>, expects <c>application/timestamp-reply</c>.
/// </summary>
public sealed class Rfc3161HttpTimestampProvider : ITimestampProvider, IDisposable
{
    private readonly HttpClientOwnership.HttpClientLease _http;
    private readonly Uri _endpoint;

    /// <summary>Initializes a new RFC 3161 HTTP timestamp provider instance.</summary>
    /// <param name="tspEndpoint">Timestamp service endpoint that accepts RFC 3161 timestamp queries.</param>
    /// <param name="httpClient">Optional HTTP client; disposed only when created internally.</param>
    public Rfc3161HttpTimestampProvider(Uri tspEndpoint, HttpClient? httpClient = null)
    {
        _endpoint = tspEndpoint ?? throw new ArgumentNullException(nameof(tspEndpoint));
        _http = new HttpClientOwnership.HttpClientLease(httpClient);
    }

    /// <summary>Requests a timestamp token asynchronously.</summary>
    /// <inheritdoc />
    /// <remarks>
    /// <paramref name="messageImprint"/> must be the raw digest octets (e.g. 32 bytes for SHA-256),
    /// not the full DER <c>MessageImprint</c> structure.
    /// </remarks>
    public async Task<byte[]> GetTimestampAsync(ReadOnlyMemory<byte> messageImprint, CancellationToken cancellationToken = default)
    {
        if (messageImprint.Length == 0)
        {
            throw new ArgumentException("Message imprint must not be empty.", nameof(messageImprint));
        }

        var gen = new TimeStampRequestGenerator();
        var nonceBytes = new byte[8];
        RandomNumberGenerator.Fill(nonceBytes);
        var nonce = new BigInteger(1, nonceBytes);
        var digest = messageImprint.ToArray();
        var request = gen.Generate(new DerObjectIdentifier(TspAlgorithms.Sha256), digest, nonce);

        using var content = new ByteArrayContent(request.GetEncoded());
        content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-query");

        using var response = await _http.Client.PostAsync(_endpoint, content, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        var tsResp = new TimeStampResponse(body);
        tsResp.Validate(request);

        if (tsResp.Status != 0 && tsResp.Status != 1)
        {
            throw new InvalidOperationException($"TSP rejected the request (status {tsResp.Status}).");
        }

        var tst = tsResp.TimeStampToken ?? throw new InvalidOperationException("TSP response contained no time-stamp token.");
        return tst.GetEncoded();
    }

    /// <summary>Disposes the internally created HTTP client, if any.</summary>
    public void Dispose() => _http.Dispose();
}
