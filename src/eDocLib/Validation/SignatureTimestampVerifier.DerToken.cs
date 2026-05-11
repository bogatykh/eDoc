using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Tsp;
using DerX509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace eDocLib.Validation;

internal static partial class SignatureTimestampVerifier
{
    /// <summary>
    /// Verifies one RFC 3161 DER time-stamp token (CMS signer checks and optional PKIX chain for the embedded TSA certificate).
    /// </summary>
    /// <remarks>
    /// This method is <c>async</c> so the <see cref="X509Certificate2"/> built from the embedded TSA certificate stays alive
    /// for the entire chain build + online revocation pipeline. A previous non-async return-Task implementation disposed the
    /// certificate as soon as the synchronous portion returned, which produced an observable use-after-dispose when
    /// <see cref="SignatureTrustPolicy.UsesApplicationControlledOnlineRevocation"/> was enabled (the asynchronous OCSP/CRL
    /// fetch continued to read certificate fields after the outer <c>using</c> had run).
    /// </remarks>
    public static async Task<TimeStampTokenDerVerifyResult> TryVerifyTimeStampTokenDerAsync(
        byte[] tokenDer,
        SignatureTrustPolicy policy,
        bool verifyCms,
        bool verifyChain,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(tokenDer);
        ArgumentNullException.ThrowIfNull(policy);

        if (!verifyCms && !verifyChain)
        {
            return TimeStampTokenDerVerifyResult.Success(null, null, null);
        }

        if (!verifyCms && verifyChain)
        {
            return TimeStampTokenDerVerifyResult.Fail(
                "Chain validation requires CMS verification for the time-stamp token.",
                null,
                null,
                null);
        }

        if (tokenDer.Length == 0)
        {
            return TimeStampTokenDerVerifyResult.Fail(
                "Time-stamp token DER is empty.",
                cmsValid: false,
                chainValid: null,
                chain: null);
        }

        if (!TryParseTimeStampToken(tokenDer, out var token, out var parseError) || token is null)
        {
            return TimeStampTokenDerVerifyResult.Fail(
                parseError ?? "Failed to parse time-stamp token.",
                null,
                null,
                null);
        }

        if (!TryGetTsaSignerCertificate(token, out DerX509Certificate? tsaSignerCert, out var certErr) || tsaSignerCert is null)
        {
            return TimeStampTokenDerVerifyResult.Fail(certErr ?? "TSA signer certificate missing.", null, null, null);
        }

        try
        {
            TspUtil.ValidateCertificate(tsaSignerCert);
        }
        catch (TspValidationException ex)
        {
            return TimeStampTokenDerVerifyResult.Fail(
                "TSA certificate is not acceptable for time-stamping: " + ex.Message,
                cmsValid: false,
                chainValid: null,
                chain: null);
        }

        var signedData = token.ToCmsSignedData();
        var verified = false;
        try
        {
            foreach (SignerInformation signer in signedData.GetSignerInfos().GetSigners())
            {
                if (signer.Verify(tsaSignerCert))
                {
                    verified = true;
                    break;
                }
            }
        }
        catch (CmsException ex)
        {
            return TimeStampTokenDerVerifyResult.Fail(
                "Time-stamp token CMS verification failed: " + ex.Message,
                cmsValid: false,
                chainValid: null,
                chain: null);
        }

        if (!verified)
        {
            return TimeStampTokenDerVerifyResult.Fail(
                "Time-stamp token CMS signature does not verify with the embedded TSA certificate.",
                cmsValid: false,
                chainValid: null,
                chain: null);
        }

        using var dotnetTsa = new X509Certificate2(tsaSignerCert.GetEncoded());
        var tslEval = EvaluateTsaTrustedList(policy, dotnetTsa);
        if (!ValidateTsaTrustedListPolicy(policy, tslEval, out var tsaTslError))
        {
            return TimeStampTokenDerVerifyResult.Fail(
                tsaTslError ?? "TSA certificate trusted-list policy failed.",
                cmsValid: true,
                chainValid: null,
                chain: null,
                tsl: tslEval);
        }

        if (!verifyChain)
        {
            return TimeStampTokenDerVerifyResult.Success(
                cmsValid: true,
                chainValid: null,
                chain: null,
                tsl: tslEval);
        }

        return await VerifyChainAndOnlineAsync(policy, dotnetTsa, tslEval, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<TimeStampTokenDerVerifyResult> VerifyChainAndOnlineAsync(
        SignatureTrustPolicy policy,
        X509Certificate2 dotnetTsa,
        TimestampAuthorityTrustedListEvaluation? tsl,
        CancellationToken cancellationToken)
    {
        using var chain = policy.CreateX509Chain();

        policy.ApplyTsaChainTrustAnchors(chain.ChainPolicy);

        var chainBuilt = chain.Build(dotnetTsa);
        var certificateChain = CertificateChainDiagnostics.FromChain(chain);
        if (!chainBuilt)
        {
            return TimeStampTokenDerVerifyResult.Fail(
                "TSA certificate chain validation failed: " + X509ChainBuildHelpers.FormatChainStatus(chain),
                cmsValid: true,
                chainValid: false,
                certificateChain,
                tsl);
        }

        var onlineOutcome = await ApplicationOnlineRevocation.TryVerifyIfRequiredAsync(
                policy,
                dotnetTsa,
                chain,
                materialFetcher: null,
                cancellationToken)
            .ConfigureAwait(false);
        if (!onlineOutcome.Ok)
        {
            return TimeStampTokenDerVerifyResult.Fail(
                onlineOutcome.Error ?? "Online revocation verification failed.",
                cmsValid: true,
                chainValid: false,
                certificateChain,
                tsl);
        }

        return TimeStampTokenDerVerifyResult.Success(cmsValid: true, chainValid: true, certificateChain, tsl);
    }

    /// <summary>
    /// Looks up <paramref name="tsaCertificate"/> in <see cref="SignatureTrustPolicy.TrustedListServiceIndex"/> (when configured)
    /// and computes mapped indicators. Returns <c>null</c> when no TSL index is configured (callers treat as "no TSL data").
    /// </summary>
    private static TimestampAuthorityTrustedListEvaluation? EvaluateTsaTrustedList(
        SignatureTrustPolicy policy,
        X509Certificate2 tsaCertificate)
    {
        if (policy.TrustedListServiceIndex is null)
        {
            return null;
        }

        if (!policy.TrustedListServiceIndex.TryGetQualification(tsaCertificate, out var q))
        {
            return new TimestampAuthorityTrustedListEvaluation(false, null, null, null);
        }

        if (policy.TrustedListQualificationReferenceTimeUtc is { } refUtc)
        {
            q = TrustedListQualificationResolver.ResolveEffectiveQualification(q, refUtc);
        }

        var indicators = TslQualificationMapper.Map(
            q.ServiceTypeIdentifiers,
            q.ServiceStatusUri,
            policy.ResolveQualificationMappingOptions());
        return new TimestampAuthorityTrustedListEvaluation(
            Listed: true,
            ServiceTypeIdentifiers: q.ServiceTypeIdentifiers,
            ServiceStatusUri: q.ServiceStatusUri,
            Indicators: indicators);
    }

    private static bool ValidateTsaTrustedListPolicy(
        SignatureTrustPolicy policy,
        TimestampAuthorityTrustedListEvaluation? tsl,
        out string? error)
    {
        error = null;
        if (!policy.RequireTimestampAuthorityCertificateListedInTrustedList
            && !policy.RequireTimestampAuthorityServiceStatusGranted
            && !policy.RequireQualifiedTimestampServiceType)
        {
            return true;
        }

        if (policy.TrustedListServiceIndex is null)
        {
            error = "TSA trusted-list check is required but TrustedListServiceIndex is not configured.";
            return false;
        }

        if (tsl is not { Listed: true } eval)
        {
            error = "TSA certificate is not listed in the configured trusted service list.";
            return false;
        }

        if (policy.RequireTimestampAuthorityServiceStatusGranted
            && eval.Indicators?.ServiceStatusIsGranted != true)
        {
            error = "TSA certificate trusted-list service status is not granted.";
            return false;
        }

        if (policy.RequireQualifiedTimestampServiceType
            && eval.Indicators?.SuggestsQualifiedTimestampService != true)
        {
            error = "TSA trusted-list service is not marked as a qualified time-stamping service "
                + "(eIDAS Art. 42 / ETSI TSA/QTST).";
            return false;
        }

        return true;
    }

    /// <summary>
    /// Reads the SHA-256 hashed message from an RFC 3161 DER token (rejects non-SHA-256 message imprint algorithm).
    /// </summary>
    public static bool TryGetTimeStampMessageImprintSha256(byte[] tokenDer, out byte[] hashedMessage, out string? error)
    {
        hashedMessage = [];
        error = null;
        ArgumentNullException.ThrowIfNull(tokenDer);
        return TryReadSha256MessageImprintFromDer(tokenDer, out hashedMessage, out error);
    }

    private static bool TryGetTsaSignerCertificate(TimeStampToken token, out DerX509Certificate? signerCert, out string? error)
    {
        signerCert = null;
        error = null;

        var signedData = token.ToCmsSignedData();
        var certStore = signedData.GetCertificates();
        var signerInfos = signedData.GetSignerInfos();
        foreach (SignerInformation signer in signerInfos.GetSigners())
        {
            foreach (DerX509Certificate match in certStore.EnumerateMatches(signer.SignerID))
            {
                signerCert = match;
                return true;
            }
        }

        error = "Could not resolve TSA signer certificate from the time-stamp token.";
        return false;
    }
}
