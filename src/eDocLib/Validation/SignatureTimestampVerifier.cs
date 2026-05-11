using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using eDocLib.Asic.Xades;

namespace eDocLib.Validation;

/// <summary>
/// Checks RFC 3161 tokens under XAdES-T <c>xades:SignatureTimeStamp</c> (imprint vs <c>SignatureValue</c>, optional CMS / PKIX).
/// </summary>
internal static partial class SignatureTimestampVerifier
{
    /// <summary>
    /// Whether the document contains an XAdES-T <c>xades:EncapsulatedTimeStamp</c> under <c>xades:SignatureTimeStamp</c>
    /// (excludes <c>xades:ArchiveTimeStamp</c> tokens).
    /// </summary>
    public static bool ContainsEmbeddedSignatureTimestamp(XmlDocument signatureDocument)
    {
        ArgumentNullException.ThrowIfNull(signatureDocument);
        return XadesUnsignedEmbeddedValues.HasEncapsulatedSignatureTimeStamp(signatureDocument);
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

        if (!TryReadSha256MessageImprintFromDer(tokenDer, out var imprintOctets, out error))
        {
            return false;
        }

        var expectedImprint = SHA256.HashData(signatureOctets);
        if (!CryptographicOperations.FixedTimeEquals(imprintOctets, expectedImprint))
        {
            error = "Time-stamp message imprint does not match SHA-256(SignatureValue bytes).";
            return false;
        }

        return true;
    }

    /// <summary>
    /// When the policy demands TSA token inspection (CMS verification, PKIX chain build, or any TSA trusted-list gate),
    /// validates the CMS time-stamp token using BouncyCastle, optionally builds a .NET PKIX chain for the TSA certificate,
    /// and applies the configured trusted-list policy gates. Returns success without inspection when no policy field
    /// requires it.
    /// </summary>
    /// <remarks>
    /// Setting any of <see cref="SignatureTrustPolicy.RequireTimestampAuthorityCertificateListedInTrustedList"/>,
    /// <see cref="SignatureTrustPolicy.RequireTimestampAuthorityServiceStatusGranted"/>, or
    /// <see cref="SignatureTrustPolicy.RequireQualifiedTimestampServiceType"/> implicitly engages CMS verification; the
    /// TSL gates cannot be enforced safely on a token whose CMS signer was never validated.
    /// </remarks>
    public static Task<TimeStampTokenDerVerifyResult> TryVerifyTsaTokenTrustAsync(
        XmlDocument signatureDocument,
        SignatureTrustPolicy policy,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signatureDocument);
        ArgumentNullException.ThrowIfNull(policy);

        if (!policy.RequiresTsaTokenInspection)
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
}
