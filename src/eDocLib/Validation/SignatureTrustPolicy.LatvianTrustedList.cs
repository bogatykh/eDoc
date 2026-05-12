using System.Net.Http;
using eDocLib.Configuration;
using eDocLib.Trust.Tsl;

namespace eDocLib.Validation;

public sealed partial class SignatureTrustPolicy
{
    /// <summary>
    /// Builds <see cref="ForLatvianEdocLtv"/> after downloading the published Latvia national trusted list using
    /// <paramref name="config"/>’s <see cref="EdocLibConfig.TslRelayUriPrefix"/> (when set) and <paramref name="httpClient"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the recommended way to obtain a production-ready LV EDOC 2.0 LTV policy with EU-trusted-list gates enabled,
    /// without manually wiring <see cref="TrustedListManager"/> and <see cref="HttpTslTrustedListProvider"/>.
    /// </para>
    /// <para>
    /// The caller owns <paramref name="httpClient"/> (timeouts, proxies, TLS). Use a single long-lived instance where possible.
    /// </para>
    /// </remarks>
    /// <param name="config">Library configuration; <see cref="EdocLibConfig.TslRelayUriPrefix"/> selects direct HTTPS vs relayed fetches.</param>
    /// <param name="httpClient">HTTP client used to download TSL bytes.</param>
    /// <param name="trustedListQualificationReferenceTimeUtc">Optional reference instant for TSL service history (see <see cref="TrustedListQualificationReferenceTimeUtc"/>).</param>
    /// <param name="verifyTrustedListXmlSignature">When <c>true</c>, requires a verifiable XML-DSig on the list (recommended for production).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Policy with non-null <see cref="TrustedListServiceIndex"/> and TSL requirement flags enabled.</returns>
    /// <exception cref="InvalidOperationException">The list could not be downloaded or parsed.</exception>
    public static async Task<SignatureTrustPolicy> ForLatvianEdocLtvWithDefaultTrustedListAsync(
        EdocLibConfig config,
        HttpClient httpClient,
        DateTimeOffset? trustedListQualificationReferenceTimeUtc = null,
        bool verifyTrustedListXmlSignature = true,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(httpClient);

        var provider = new HttpTslTrustedListProvider(httpClient, config.TslRelayUriPrefix);
        var manager = new TrustedListManager(provider);
        var (loadResult, error) = await manager.LoadAsync(
                TslPublicationUris.LatviaTerritoryKey,
                verifyTrustedListXmlSignature,
                cancellationToken)
            .ConfigureAwait(false);

        if (loadResult is null)
        {
            throw new InvalidOperationException(
                error ?? "Failed to load the Latvian trusted service list (TSL).");
        }

        return ForLatvianEdocLtv(loadResult.Index, trustedListQualificationReferenceTimeUtc);
    }
}
