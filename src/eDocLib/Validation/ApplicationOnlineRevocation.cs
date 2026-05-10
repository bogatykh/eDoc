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
    /// Runs network revocation on a thread-pool thread to avoid deadlocks when callers have a <see cref="SynchronizationContext"/>.
    /// A single-element chain is skipped only when the end-entity is self-signed (raw subject == issuer).
    /// When verification runs and HTTP completes, <paramref name="fetchedMaterial"/> is the last fetch result (possibly empty OCSP/CRL lists).
    /// Otherwise <c>null</c>.
    /// </summary>
    /// <param name="policy">Signature trust policy that controls whether online revocation is required.</param>
    /// <param name="endEntity">Certificate whose revocation status is checked.</param>
    /// <param name="chain">Built certificate chain for the end-entity certificate.</param>
    /// <param name="error">Failure message when verification does not complete successfully.</param>
    /// <param name="fetchedMaterial">Fetched OCSP and CRL DER when HTTP fetch completed.</param>
    /// <param name="artifactOutcomes">Detailed verification outcomes for fetched artifacts.</param>
    /// <param name="materialFetcher">Optional fetcher; default uses <see cref="CertificateRevocationMaterialFetcher"/>.</param>
    public static bool TryVerifyIfRequired(
        SignatureTrustPolicy policy,
        X509Certificate2 endEntity,
        X509Chain chain,
        out string? error,
        out RevocationMaterialFetchResult? fetchedMaterial,
        out IReadOnlyList<RevocationArtifactOutcome>? artifactOutcomes,
        IRevocationMaterialFetcher? materialFetcher = null)
    {
        error = null;
        fetchedMaterial = null;
        artifactOutcomes = null;
        if (!policy.UsesApplicationControlledOnlineRevocation)
        {
            return true;
        }

        try
        {
            policy.ValidateRevocationFetchConfiguration();
        }
        catch (InvalidOperationException ex)
        {
            error = ex.Message;
            return false;
        }

        var fetcher = materialFetcher ?? RevocationMaterialFetcherDefaults.Instance;

        try
        {
            var (ok, err, fetched, artifacts) =
                Task.Run(() => TryVerifyIfRequiredAsync(policy, endEntity, chain, fetcher)).GetAwaiter().GetResult();
            error = err;
            fetchedMaterial = fetched;
            artifactOutcomes = artifacts;
            return ok;
        }
        catch (Exception ex)
        {
            error = "Online revocation failed: " + ex.Message;
            return false;
        }
    }

    /// <summary>Stores the task.</summary>
    private static async Task<(
        bool Ok,
        string? Error,
        RevocationMaterialFetchResult? Fetched,
        IReadOnlyList<RevocationArtifactOutcome>? Artifacts)> TryVerifyIfRequiredAsync(
        SignatureTrustPolicy policy,
        X509Certificate2 endEntity,
        X509Chain chain,
        IRevocationMaterialFetcher materialFetcher)
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
        var path = new X509Certificate2[chain.ChainElements.Count];
        for (var i = 0; i < chain.ChainElements.Count; i++)
        {
            path[i] = chain.ChainElements[i].Certificate;
        }

        RevocationMaterialFetchResult fetched;
        try
        {
            fetched = await FetchWithPolicyTimeoutAsync(policy, endEntity, issuer, materialFetcher).ConfigureAwait(false);
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

    /// <summary>Fetches with policy timeout async.</summary>
    private static async Task<RevocationMaterialFetchResult> FetchWithPolicyTimeoutAsync(
        SignatureTrustPolicy policy,
        X509Certificate2 endEntity,
        X509Certificate2 issuer,
        IRevocationMaterialFetcher materialFetcher)
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
            return await FetchAsync(policy.RevocationFetchCancellationToken).ConfigureAwait(false);
        }

        using var timeoutCts = new CancellationTokenSource(policy.RevocationFetchTimeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(
            timeoutCts.Token,
            policy.RevocationFetchCancellationToken);
        return await FetchAsync(linked.Token).ConfigureAwait(false);
    }

    /// <summary>Returns whether self signed end entity.</summary>
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
