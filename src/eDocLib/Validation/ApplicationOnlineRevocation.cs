using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using eDocLib.Revocation;
using eDocLib.Revocation.Online;
using eDocLib.Revocation.Verify;

namespace eDocLib.Validation;

/// <summary>
/// When <see cref="SignatureTrustPolicy.UsesApplicationControlledOnlineRevocation"/> is <c>true</c>, fetches OCSP/CRL over HTTP
/// and verifies them after PKIX chain build.
/// </summary>
internal static class ApplicationOnlineRevocation
{
    /// <summary>
    /// Fetches and verifies OCSP/CRL when policy requires application-controlled online revocation.
    /// A single-element chain is skipped only when the end-entity is self-signed (raw subject == issuer).
    /// When verification runs and HTTP completes, <see cref="OnlineRevocationOutcome.Fetched"/> is the last fetch result (possibly empty OCSP/CRL lists); otherwise <c>null</c>.
    /// </summary>
    /// <param name="policy">Trust policy; must pass <see cref="SignatureTrustPolicy.ValidateRevocationFetchConfiguration"/> when online revocation is enabled.</param>
    /// <param name="endEntity">Leaf certificate whose revocation status is checked.</param>
    /// <param name="chain">Built PKIX chain for <paramref name="endEntity"/>.</param>
    /// <param name="materialFetcher">Optional OCSP/CRL fetcher; default uses <see cref="CertificateRevocationMaterialFetcher"/>.</param>
    /// <param name="cancellationToken">Linked with policy timeout and <see cref="SignatureTrustPolicy.RevocationFetchCancellationToken"/> for the HTTP fetch.</param>
    public static ValueTask<OnlineRevocationOutcome> TryVerifyIfRequiredAsync(
        SignatureTrustPolicy policy,
        X509Certificate2 endEntity,
        X509Chain chain,
        IRevocationMaterialFetcher? materialFetcher = null,
        CancellationToken cancellationToken = default)
    {
        if (!policy.UsesApplicationControlledOnlineRevocation)
        {
            return new ValueTask<OnlineRevocationOutcome>(OnlineRevocationOutcome.SuccessNoFetch);
        }

        try
        {
            policy.ValidateRevocationFetchConfiguration();
        }
        catch (InvalidOperationException ex)
        {
            return new ValueTask<OnlineRevocationOutcome>(OnlineRevocationOutcome.Failed(ex.Message));
        }

        var fetcher = materialFetcher ?? RevocationMaterialFetcherDefaults.Instance;
        return RunAsync(policy, endEntity, chain, fetcher, cancellationToken);

        static async ValueTask<OnlineRevocationOutcome> RunAsync(
            SignatureTrustPolicy policy,
            X509Certificate2 endEntity,
            X509Chain chain,
            IRevocationMaterialFetcher materialFetcher,
            CancellationToken cancellationToken)
        {
            try
            {
                var (ok, err, fetched, artifacts) =
                    await VerifyCoreAsync(policy, endEntity, chain, materialFetcher, cancellationToken).ConfigureAwait(false);
                return new OnlineRevocationOutcome(ok, err, fetched, artifacts);
            }
            catch (Exception ex)
            {
                return OnlineRevocationOutcome.Failed("Online revocation failed: " + ex.Message);
            }
        }
    }

    private static async Task<(
        bool Ok,
        string? Error,
        RevocationMaterialFetchResult? Fetched,
        IReadOnlyList<RevocationArtifactOutcome>? Artifacts)> VerifyCoreAsync(
        SignatureTrustPolicy policy,
        X509Certificate2 endEntity,
        X509Chain chain,
        IRevocationMaterialFetcher materialFetcher,
        CancellationToken cancellationToken)
    {
        if (chain.ChainElements.Count < 2)
        {
            var leaf = chain.ChainElements[0].Certificate;
            if (IsSelfSignedEndEntity(leaf))
            {
                return (true, null, null, null);
            }

            return (
                false,
                "Online revocation requires a PKIX path with at least two certificates (end-entity and issuer), or a self-signed end-entity.",
                null,
                null);
        }

        var issuer = chain.ChainElements[1].Certificate;
        var path = X509ChainBuildHelpers.ToCertificatePath(chain);

        RevocationMaterialFetchResult fetched;
        try
        {
            fetched = await FetchWithPolicyTimeoutAsync(policy, endEntity, issuer, materialFetcher, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return (false, "Online revocation fetch was cancelled or timed out.", null, null);
        }
        catch (Exception ex)
        {
            return (false, "Online revocation HTTP fetch failed: " + ex.Message, null, null);
        }

        if (!OnlineRevocationVerifier.TryVerifyFetchedDetailed(
                endEntity,
                fetched,
                path,
                out var verErr,
                out var artifacts,
                policy.BuildEmbeddedOcspStrictOptions(),
                policy.ExtraChainCertificates))
        {
            return (false, verErr, fetched, artifacts);
        }

        return (true, null, fetched, artifacts);
    }

    private static async Task<RevocationMaterialFetchResult> FetchWithPolicyTimeoutAsync(
        SignatureTrustPolicy policy,
        X509Certificate2 endEntity,
        X509Certificate2 issuer,
        IRevocationMaterialFetcher materialFetcher,
        CancellationToken callerCancellationToken)
    {
        Task<RevocationMaterialFetchResult> FetchAsync(CancellationToken ct) =>
            materialFetcher.FetchAsync(
                endEntity,
                issuer,
                policy.RevocationHttpClient!,
                policy.RevocationMaxResponseBytes,
                policy.RevocationRejectLiteralPrivateAndLoopbackHosts,
                policy.RevocationDerCache,
                policy.RevocationFetchDeltaCrlViaFreshestCdp,
                ct);

        if (policy.RevocationFetchTimeout == Timeout.InfiniteTimeSpan)
        {
            using var linkedNoTimeout = CancellationTokenSource.CreateLinkedTokenSource(
                policy.RevocationFetchCancellationToken,
                callerCancellationToken);
            return await FetchAsync(linkedNoTimeout.Token).ConfigureAwait(false);
        }

        using var timeoutCts = new CancellationTokenSource(policy.RevocationFetchTimeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(
            timeoutCts.Token,
            policy.RevocationFetchCancellationToken,
            callerCancellationToken);
        return await FetchAsync(linked.Token).ConfigureAwait(false);
    }

    private static bool IsSelfSignedEndEntity(X509Certificate2 cert)
    {
        try
        {
            return cert.SubjectName.RawData.AsSpan().SequenceEqual(cert.IssuerName.RawData.AsSpan());
        }
        catch
        {
            return false;
        }
    }
}
