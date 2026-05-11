namespace eDocLib.Trust.Tsl;

/// <summary>
/// Downloads TSL XML over HTTPS. Optional relay: if <see cref="TslRelayUriPrefix"/> is set, the final
/// request URI is <c>prefix + Uri.EscapeDataString(targetUrl)</c> (common pattern for appending
/// the real publication URL as a single query value).
/// </summary>
public sealed class HttpTslTrustedListProvider : ITrustedListProvider
{
    private readonly HttpClient _http;
    private readonly string? _relayPrefix;

    /// <summary>Initializes a new HTTP TSL trusted list provider instance.</summary>
    /// <param name="httpClient">Caller-owned client (timeouts, TLS, proxies).</param>
    /// <param name="tslRelayUriPrefix">
    /// When non-empty, fetch via this prefix plus percent-encoded target URL; when null/empty, GET the target URL directly.
    /// </param>
    public HttpTslTrustedListProvider(HttpClient httpClient, string? tslRelayUriPrefix = null)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        _http = httpClient;
        _relayPrefix = string.IsNullOrWhiteSpace(tslRelayUriPrefix) ? null : tslRelayUriPrefix.TrimEnd();
    }

    /// <summary>Configured relay prefix, if any.</summary>
    public string? TslRelayUriPrefix => _relayPrefix;

    /// <inheritdoc />
    /// <remarks>
    /// <list type="bullet">
    /// <item><description><c>EU</c> — EU LOTL.</description></item>
    /// <item><description><c>EU-TC</c> — EU third-country AdES LOTL.</description></item>
    /// <item><description><c>LV</c> — Latvia national TSL on <c>trustlist.gov.lv</c> (<see cref="TslPublicationUris.LatviaNationalTrustedList"/>).</description></item>
    /// <item><description>Other two-letter ISO territories — national TSL URL resolved from EU LOTL <c>OtherTSLPointer</c> entries.</description></item>
    /// <item><description>Absolute <c>https://</c> or <c>http://</c> — that resource.</description></item>
    /// </list>
    /// </remarks>
    public async Task<Stream> GetTrustedListAsync(string territory, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(territory);
        var key = territory.Trim();
        if (key.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            key.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            if (!Uri.TryCreate(key, UriKind.Absolute, out var absolute) ||
                absolute.Scheme != Uri.UriSchemeHttp && absolute.Scheme != Uri.UriSchemeHttps)
                throw new ArgumentException("Only http(s) absolute URLs are allowed.", nameof(territory));

            return await FetchToMemoryAsync(absolute.ToString(), cancellationToken).ConfigureAwait(false);
        }

        var upper = key.ToUpperInvariant();
        if (upper == TslPublicationUris.EuLotlTerritoryKey)
            return await FetchToMemoryAsync(TslPublicationUris.EuListOfTrustedLists, cancellationToken)
                .ConfigureAwait(false);

        if (upper == TslPublicationUris.EuTcAdesLotlTerritoryKey)
            return await FetchToMemoryAsync(TslPublicationUris.EuThirdCountryAdesListOfTrustedLists, cancellationToken)
                .ConfigureAwait(false);

        if (upper == TslPublicationUris.LatviaTerritoryKey)
            return await FetchToMemoryAsync(TslPublicationUris.LatviaNationalTrustedList, cancellationToken)
                .ConfigureAwait(false);

        if (upper.Length == 2 && char.IsAsciiLetter(upper[0]) && char.IsAsciiLetter(upper[1]))
        {
            await using var lotl = await FetchToMemoryAsync(TslPublicationUris.EuListOfTrustedLists, cancellationToken)
                .ConfigureAwait(false);
            if (!EuLotlPointerLocator.TryGetNationalTslUrl(lotl, upper, out var nationalUrl) || nationalUrl is null)
                throw new InvalidOperationException(
                    $"No TSLLocation for territory '{upper}' in EU LOTL ({TslPublicationUris.EuListOfTrustedLists}).");

            return await FetchToMemoryAsync(nationalUrl, cancellationToken).ConfigureAwait(false);
        }

        throw new ArgumentException(
            "Unknown territory key. Use EU, EU-TC, a two-letter ISO code, or an absolute http(s) URL.",
            nameof(territory));
    }

    private async Task<MemoryStream> FetchToMemoryAsync(string targetUrl, CancellationToken cancellationToken)
    {
        var requestUri = _relayPrefix is null ? targetUrl : _relayPrefix + Uri.EscapeDataString(targetUrl);
        using var response = await _http.GetAsync(requestUri, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        await using var network = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        var ms = new MemoryStream();
        await network.CopyToAsync(ms, cancellationToken).ConfigureAwait(false);
        ms.Position = 0;
        return ms;
    }
}
