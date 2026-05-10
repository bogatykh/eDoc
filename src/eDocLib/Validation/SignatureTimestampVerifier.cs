using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Tsp;
using DerX509Certificate = Org.BouncyCastle.X509.X509Certificate;
using eDocLib.Asic.Xades;

namespace eDocLib.Validation;

/// <summary>
/// Checks RFC 3161 tokens under XAdES-T <c>xades:SignatureTimeStamp</c> (imprint vs <c>SignatureValue</c>, optional CMS / PKIX)
/// and archive tokens under <c>xades:ArchiveTimeStamp</c> via <see cref="TryVerifyTimeStampTokenDer"/>.
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
    /// <param name="tokenDer">DER-encoded RFC 3161 time-stamp token.</param>
    /// <param name="policy">Trust policy used for TSA certificate chain validation.</param>
    /// <param name="verifyCms">When <c>false</c> and <paramref name="verifyChain"/> is <c>false</c>, returns success without parsing.</param>
    /// <param name="verifyChain">PKIX validation after CMS success (same roots policy as <see cref="SignatureTrustPolicy.ValidateTsaSignerChain"/>).</param>
    /// <param name="error">Failure message when verification fails.</param>
    /// <param name="cmsValid">Whether CMS signer verification succeeded when attempted.</param>
    /// <param name="chainValid">Whether TSA certificate chain validation succeeded when attempted.</param>
    /// <param name="certificateChain">TSA certificate chain diagnostics when chain validation ran.</param>
    public static bool TryVerifyTimeStampTokenDer(
        byte[] tokenDer,
        SignatureTrustPolicy policy,
        bool verifyCms,
        bool verifyChain,
        out string? error,
        out bool? cmsValid,
        out bool? chainValid,
        out IReadOnlyList<CertificateChainDiagnostic>? certificateChain)
    {
        ArgumentNullException.ThrowIfNull(tokenDer);
        ArgumentNullException.ThrowIfNull(policy);
        error = null;
        cmsValid = null;
        chainValid = null;
        certificateChain = null;

        if (!verifyCms && !verifyChain)
        {
            return true;
        }

        if (!verifyCms && verifyChain)
        {
            error = "Chain validation requires CMS verification for the time-stamp token.";
            return false;
        }

        if (tokenDer.Length == 0)
        {
            error = "Time-stamp token DER is empty.";
            cmsValid = false;
            return false;
        }

        TimeStampToken token;
        try
        {
            token = new TimeStampToken(new CmsSignedData(tokenDer));
        }
        catch (Exception ex) when (ex is TspException or CmsException)
        {
            error = "Failed to parse time-stamp token: " + ex.Message;
            return false;
        }

        if (!TryGetTsaSignerCertificate(token, out DerX509Certificate? tsaSignerCert, out error) || tsaSignerCert == null)
        {
            return false;
        }

        try
        {
            TspUtil.ValidateCertificate(tsaSignerCert);
        }
        catch (TspValidationException ex)
        {
            error = "TSA certificate is not acceptable for time-stamping: " + ex.Message;
            cmsValid = false;
            return false;
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
            error = "Time-stamp token CMS verification failed: " + ex.Message;
            cmsValid = false;
            return false;
        }

        if (!verified)
        {
            error = "Time-stamp token CMS signature does not verify with the embedded TSA certificate.";
            cmsValid = false;
            return false;
        }

        cmsValid = true;

        if (!verifyChain)
        {
            return true;
        }

        using var dotnetTsa = new X509Certificate2(tsaSignerCert.GetEncoded());
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        policy.ApplyRevocationMode(chain.ChainPolicy);

        var tsaRoots = policy.TsaTrustAnchors is { Count: > 0 }
            ? policy.TsaTrustAnchors
            : policy.CustomTrustAnchors;

        if (tsaRoots is { Count: > 0 })
        {
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            foreach (X509Certificate2 anchor in tsaRoots)
            {
                chain.ChainPolicy.CustomTrustStore.Add(anchor);
            }
        }

        var chainBuilt = chain.Build(dotnetTsa);
        certificateChain = CertificateChainDiagnostics.FromChain(chain);
        if (!chainBuilt)
        {
            var status = chain.ChainStatus.Length > 0
                ? string.Join("; ", chain.ChainStatus.Select(s => s.StatusInformation.Trim()))
                : "Unknown chain error.";
            error = "TSA certificate chain validation failed: " + status;
            chainValid = false;
            return false;
        }

        if (!ApplicationOnlineRevocation.TryVerifyIfRequired(
                policy,
                dotnetTsa,
                chain,
                out var onlineRevocationError,
                out _,
                out _))
        {
            error = onlineRevocationError;
            chainValid = false;
            return false;
        }

        chainValid = true;
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

    /// <summary>
    /// When <see cref="SignatureTrustPolicy.ValidateTsaSigner"/> or <see cref="SignatureTrustPolicy.ValidateTsaSignerChain"/> is set,
    /// validates the CMS time-stamp token using BouncyCastle (and optionally builds a .NET PKIX chain for the TSA certificate).
    /// </summary>
    /// <param name="signatureDocument">Signature XML document containing a signature timestamp token.</param>
    /// <param name="policy">Trust policy that controls TSA signer and chain validation.</param>
    /// <param name="error">Failure message when validation fails.</param>
    /// <param name="tsaCmsValid">
    /// <c>null</c> if not attempted; <c>false</c> if CMS/signer validation failed; <c>true</c> if it succeeded.
    /// </param>
    /// <param name="tsaChainValid">
    /// <c>null</c> if chain validation was not requested or not reached; <c>false</c> if it failed after CMS success; <c>true</c> if it succeeded.
    /// </param>
    /// <param name="tsaCertificateChain">
    /// Populated when <see cref="SignatureTrustPolicy.ValidateTsaSignerChain"/> is <c>true</c> after <see cref="X509Chain.Build"/> (success or failure).
    /// </param>
    public static bool TryVerifyTsaTokenTrust(
        XmlDocument signatureDocument,
        SignatureTrustPolicy policy,
        out string? error,
        out bool? tsaCmsValid,
        out bool? tsaChainValid,
        out IReadOnlyList<CertificateChainDiagnostic>? tsaCertificateChain)
    {
        ArgumentNullException.ThrowIfNull(signatureDocument);
        ArgumentNullException.ThrowIfNull(policy);
        error = null;
        tsaCmsValid = null;
        tsaChainValid = null;
        tsaCertificateChain = null;

        var wantCms = policy.ValidateTsaSigner || policy.ValidateTsaSignerChain;
        if (!wantCms)
        {
            return true;
        }

        if (!TryGetEncapsulatedTimestampDer(signatureDocument, out var tokenDer, out error))
        {
            return false;
        }

        return TryVerifyTimeStampTokenDer(
            tokenDer,
            policy,
            verifyCms: true,
            verifyChain: policy.ValidateTsaSignerChain,
            out error,
            out tsaCmsValid,
            out tsaChainValid,
            out tsaCertificateChain);
    }

    /// <summary>Attempts to get signature value octets.</summary>
    private static bool TryGetSignatureValueOctets(XmlDocument signatureDocument, out byte[] octets, out string? error)
    {
        octets = [];
        error = null;

        var sigValueNodes = signatureDocument.GetElementsByTagName("SignatureValue", SignedXml.XmlDsigNamespaceUrl);
        if (sigValueNodes.Count == 0 || sigValueNodes[0] is not XmlElement)
        {
            error = "SignatureValue is missing.";
            return false;
        }

        var svText = ((XmlElement)sigValueNodes[0]!).InnerText.Trim();
        if (svText.Length == 0)
        {
            error = "SignatureValue is empty.";
            return false;
        }

        try
        {
            octets = Convert.FromBase64String(svText);
        }
        catch (FormatException)
        {
            error = "SignatureValue is not valid Base64.";
            return false;
        }

        return true;
    }

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
