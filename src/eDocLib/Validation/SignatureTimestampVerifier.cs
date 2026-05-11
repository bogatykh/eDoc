using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Tsp;
using DerX509Certificate = Org.BouncyCastle.X509.X509Certificate;
using eDocLib.Asic.Xades;

namespace eDocLib.Validation;

/// <summary>
/// Checks RFC 3161 tokens under XAdES-T <c>xades:SignatureTimeStamp</c> (imprint vs <c>SignatureValue</c>, optional CMS / PKIX)
/// and archive tokens under <c>xades:ArchiveTimeStamp</c> via <see cref="TryVerifyTimeStampTokenDerAsync"/>.
/// </summary>
internal static class SignatureTimestampVerifier
{
    /// <summary>
    /// Whether the document contains an XAdES-T <c>xades:EncapsulatedTimeStamp</c> under <c>xades:SignatureTimeStamp</c>
    /// (excludes <c>xades:ArchiveTimeStamp</c> tokens).
    /// </summary>
    public static bool ContainsEmbeddedSignatureTimestamp(XmlDocument signatureDocument)
    {
        ArgumentNullException.ThrowIfNull(signatureDocument);
        return XadesUnsignedEmbeddedValues.ReadEncapsulatedSignatureTimeStamps(signatureDocument).Count > 0;
    }

    /// <summary>
    /// Locates the first <c>xades:EncapsulatedTimeStamp</c> under <c>SignatureTimeStamp</c>, parses it as a CMS time-stamp token,
    /// and compares its SHA-256 message imprint to <c>SHA256( DecodeBase64(SignatureValue) )</c>.
    /// </summary>
    public static bool TryVerifySignatureTimeStampImprint(XmlDocument signatureDocument, out string? error)
    {
        ArgumentNullException.ThrowIfNull(signatureDocument);
        error = null;

        if (!TryGetEncapsulatedTimestampDer(signatureDocument, out var tokenDer, out error))
        {
            return false;
        }

        if (!TryGetSignatureValueOctets(signatureDocument, out var signatureOctets, out error))
        {
            return false;
        }

        var expectedImprint = SHA256.HashData(signatureOctets);

        try
        {
            var token = new TimeStampToken(new CmsSignedData(tokenDer));
            var info = token.TimeStampInfo;
            if (!string.Equals(info.MessageImprintAlgOid, TspAlgorithms.Sha256, StringComparison.Ordinal))
            {
                error = $"Time-stamp imprint uses algorithm {info.MessageImprintAlgOid}, expected {TspAlgorithms.Sha256}.";
                return false;
            }

            var hashed = info.TstInfo.MessageImprint.GetHashedMessage();
            if (hashed == null || !CryptographicOperations.FixedTimeEquals(hashed, expectedImprint))
            {
                error = "Time-stamp message imprint does not match SHA-256(SignatureValue bytes).";
                return false;
            }
        }
        catch (Exception ex) when (ex is TspException or CmsException)
        {
            error = "Failed to parse time-stamp token: " + ex.Message;
            return false;
        }

        return true;
    }

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

        TimeStampToken token;
        try
        {
            token = new TimeStampToken(new CmsSignedData(tokenDer));
        }
        catch (Exception ex) when (ex is TspException or CmsException)
        {
            return Task.FromResult(TimeStampTokenDerVerifyResult.Fail(
                "Failed to parse time-stamp token: " + ex.Message,
                null,
                null,
                null));
        }

        if (!TryGetTsaSignerCertificate(token, out DerX509Certificate? tsaSignerCert, out var certErr) || tsaSignerCert == null)
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
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        policy.ApplyRevocationMode(chain.ChainPolicy);

        var tsaRoots = policy.TsaTrustAnchors is { Count: > 0 }
            ? policy.TsaTrustAnchors
            : policy.CustomTrustAnchors;
        X509ChainBuildHelpers.ApplyTrustAnchors(chain.ChainPolicy, tsaRoots);

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
    /// When <see cref="SignatureTrustPolicy.ValidateTsaSigner"/> or <see cref="SignatureTrustPolicy.ValidateTsaSignerChain"/> is set,
    /// validates the CMS time-stamp token using BouncyCastle (and optionally builds a .NET PKIX chain for the TSA certificate).
    /// </summary>
    public static Task<TimeStampTokenDerVerifyResult> TryVerifyTsaTokenTrustAsync(
        XmlDocument signatureDocument,
        SignatureTrustPolicy policy,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signatureDocument);
        ArgumentNullException.ThrowIfNull(policy);

        var wantCms = policy.ValidateTsaSigner || policy.ValidateTsaSignerChain;
        if (!wantCms)
        {
            return Task.FromResult(TimeStampTokenDerVerifyResult.Success(null, null, null));
        }

        if (!TryGetEncapsulatedTimestampDer(signatureDocument, out var tokenDer, out var error))
        {
            return Task.FromResult(TimeStampTokenDerVerifyResult.Fail(error ?? "No encapsulated timestamp.", null, null, null));
        }

        return TryVerifyTimeStampTokenDerAsync(
            tokenDer,
            policy,
            verifyCms: true,
            verifyChain: policy.ValidateTsaSignerChain,
            cancellationToken);
    }

    /// <summary>
    /// Reads the SHA-256 hashed message from an RFC 3161 DER token (rejects non-SHA-256 message imprint algorithm).
    /// </summary>
    public static bool TryGetTimeStampMessageImprintSha256(byte[] tokenDer, out byte[] hashedMessage, out string? error)
    {
        hashedMessage = [];
        error = null;
        ArgumentNullException.ThrowIfNull(tokenDer);

        try
        {
            var token = new TimeStampToken(new CmsSignedData(tokenDer));
            var info = token.TimeStampInfo;
            if (!string.Equals(info.MessageImprintAlgOid, TspAlgorithms.Sha256, StringComparison.Ordinal))
            {
                error = $"Time-stamp imprint uses algorithm {info.MessageImprintAlgOid}, expected SHA-256.";
                return false;
            }

            var hashed = info.TstInfo.MessageImprint.GetHashedMessage();
            if (hashed == null || hashed.Length == 0)
            {
                error = "Time-stamp message imprint is missing.";
                return false;
            }

            hashedMessage = hashed;
            return true;
        }
        catch (Exception ex) when (ex is TspException or CmsException)
        {
            error = "Failed to parse time-stamp token: " + ex.Message;
            return false;
        }
    }

    /// <summary>Attempts to get signature value octets.</summary>
    private static bool TryGetSignatureValueOctets(XmlDocument signatureDocument, out byte[] octets, out string? error) =>
        SignatureValueReader.TryReadOctets(signatureDocument, out octets, out error);

    /// <summary>Attempts to get encapsulated timestamp DER.</summary>
    private static bool TryGetEncapsulatedTimestampDer(XmlDocument signatureDocument, out byte[] tokenDer, out string? error)
    {
        tokenDer = [];
        error = null;

        var sigTs = XadesUnsignedEmbeddedValues.ReadEncapsulatedSignatureTimeStamps(signatureDocument);
        if (sigTs.Count == 0)
        {
            error = "No xades:SignatureTimeStamp/xades:EncapsulatedTimeStamp element found.";
            return false;
        }

        tokenDer = sigTs[0];
        return true;
    }

    /// <summary>Attempts to get TSA signer certificate.</summary>
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
