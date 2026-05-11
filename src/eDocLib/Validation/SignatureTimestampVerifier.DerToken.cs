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
    public static Task<TimeStampTokenDerVerifyResult> TryVerifyTimeStampTokenDerAsync(
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
            return Task.FromResult(TimeStampTokenDerVerifyResult.Success(null, null, null));
        }

        if (!verifyCms && verifyChain)
        {
            return Task.FromResult(TimeStampTokenDerVerifyResult.Fail(
                "Chain validation requires CMS verification for the time-stamp token.",
                null,
                null,
                null));
        }

        if (tokenDer.Length == 0)
        {
            return Task.FromResult(TimeStampTokenDerVerifyResult.Fail(
                "Time-stamp token DER is empty.",
                cmsValid: false,
                chainValid: null,
                chain: null));
        }

        if (!TryParseTimeStampToken(tokenDer, out var token, out var parseError) || token is null)
        {
            return Task.FromResult(TimeStampTokenDerVerifyResult.Fail(
                parseError ?? "Failed to parse time-stamp token.",
                null,
                null,
                null));
        }

        if (!TryGetTsaSignerCertificate(token, out DerX509Certificate? tsaSignerCert, out var certErr) || tsaSignerCert is null)
        {
            return Task.FromResult(TimeStampTokenDerVerifyResult.Fail(certErr ?? "TSA signer certificate missing.", null, null, null));
        }

        try
        {
            TspUtil.ValidateCertificate(tsaSignerCert);
        }
        catch (TspValidationException ex)
        {
            return Task.FromResult(TimeStampTokenDerVerifyResult.Fail(
                "TSA certificate is not acceptable for time-stamping: " + ex.Message,
                cmsValid: false,
                chainValid: null,
                chain: null));
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
            return Task.FromResult(TimeStampTokenDerVerifyResult.Fail(
                "Time-stamp token CMS verification failed: " + ex.Message,
                cmsValid: false,
                chainValid: null,
                chain: null));
        }

        if (!verified)
        {
            return Task.FromResult(TimeStampTokenDerVerifyResult.Fail(
                "Time-stamp token CMS signature does not verify with the embedded TSA certificate.",
                cmsValid: false,
                chainValid: null,
                chain: null));
        }

        if (!verifyChain)
        {
            return Task.FromResult(TimeStampTokenDerVerifyResult.Success(cmsValid: true, chainValid: null, chain: null));
        }

        return VerifyChainAndOnlineAsync(policy, tsaSignerCert, cancellationToken);
    }

    private static async Task<TimeStampTokenDerVerifyResult> VerifyChainAndOnlineAsync(
        SignatureTrustPolicy policy,
        DerX509Certificate tsaSignerCert,
        CancellationToken cancellationToken)
    {
        using var dotnetTsa = new X509Certificate2(tsaSignerCert.GetEncoded());
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
                certificateChain);
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
                certificateChain);
        }

        return TimeStampTokenDerVerifyResult.Success(cmsValid: true, chainValid: true, certificateChain);
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
