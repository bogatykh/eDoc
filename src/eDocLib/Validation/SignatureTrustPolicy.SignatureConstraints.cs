using System.Security.Cryptography.X509Certificates;
using eDocLib.Revocation;

namespace eDocLib.Validation;

public sealed partial class SignatureTrustPolicy
{
    /// <summary>
    /// After a successful PKIX chain build, verify unsigned XAdES <c>RevocationValues</c> when present (OCSP/CRL DER).
    /// Does not fetch revocation from the network and does not change <see cref="X509Chain"/> revocation checks —
    /// only validates material already embedded in the signature. Requires <see cref="ValidateCertificateChain"/> to succeed
    /// before this runs; see unsigned <c>RevocationValues</c> verification in the validation pipeline.
    /// </summary>
    public bool VerifyUnsignedRevocationWhenPresent { get; init; }

    /// <summary>
    /// When <c>true</c> together with <see cref="VerifyUnsignedRevocationWhenPresent"/>, embedded OCSP must verify using a
    /// responder certificate carried inside the OCSP response (no “any chain CA key” fallback). See
    /// <see cref="EmbeddedRevocationVerificationOptions.RequireOcspSignatureByEmbeddedResponderOnly"/>.
    /// </summary>
    public bool StrictEmbeddedOcspRequireEmbeddedResponderSignature { get; init; }

    /// <summary>
    /// When <c>true</c> together with <see cref="VerifyUnsignedRevocationWhenPresent"/>, the embedded OCSP responder
    /// certificate must declare the id-kp-OCSPSigning extended key usage.
    /// </summary>
    public bool StrictEmbeddedOcspRequireResponderOcspSigningEku { get; init; }

    /// <summary>
    /// When <c>true</c> together with <see cref="VerifyUnsignedRevocationWhenPresent"/>, the embedded OCSP responder
    /// certificate must chain to <see cref="CustomTrustAnchors"/> (or the OS store when anchors are not set), using
    /// <see cref="ExtraChainCertificates"/> as <c>ExtraStore</c>. See <see cref="EmbeddedRevocationVerificationOptions.ValidateEmbeddedOcspResponderCertificateChain"/>.
    /// </summary>
    public bool StrictEmbeddedOcspValidateResponderCertificateChain { get; init; }

    /// <summary>
    /// Non-<c>null</c> when any strict embedded/online OCSP policy flag is set; pass to
    /// embedded- and online-revocation verification paths in the validation pipeline.
    /// </summary>
    public EmbeddedRevocationVerificationOptions? BuildEmbeddedOcspStrictOptions()
    {
        if (!StrictEmbeddedOcspRequireEmbeddedResponderSignature
            && !StrictEmbeddedOcspRequireResponderOcspSigningEku
            && !StrictEmbeddedOcspValidateResponderCertificateChain)
        {
            return null;
        }

        return new EmbeddedRevocationVerificationOptions
        {
            RequireOcspSignatureByEmbeddedResponderOnly = StrictEmbeddedOcspRequireEmbeddedResponderSignature,
            RequireEmbeddedResponderOcspSigningExtendedKeyUsage = StrictEmbeddedOcspRequireResponderOcspSigningEku,
            ValidateEmbeddedOcspResponderCertificateChain = StrictEmbeddedOcspValidateResponderCertificateChain,
            ResponderChainTrustAnchors = CustomTrustAnchors,
            ResponderChainExtraStore = ExtraChainCertificates,
        };
    }

    /// <summary>
    /// <c>true</c> when any policy field forces the validator to inspect the embedded RFC 3161 token (CMS verification,
    /// PKIX chain build, or a TSA trusted-list gate). Used by the validation pipeline so that setting only a TSA
    /// trusted-list gate (without <see cref="ValidateTsaSigner"/>) still triggers CMS verification — a TSL listing
    /// check on a token whose CMS signature was never verified would be exploitable.
    /// </summary>
    internal bool RequiresTsaTokenInspection =>
        ValidateTsaSigner
        || ValidateTsaSignerChain
        || RequireTimestampAuthorityCertificateListedInTrustedList
        || RequireTimestampAuthorityServiceStatusGranted
        || RequireQualifiedTimestampServiceType;

    /// <summary>
    /// When <c>true</c>, validation fails if <c>xades:SigningCertificate</c> is missing. When <c>false</c>, a missing element is allowed;
    /// if the element is present, the pipeline still verifies digest and IssuerSerial against <c>KeyInfo</c>.
    /// </summary>
    public bool RequireXadesSigningCertificate { get; init; }

    /// <summary>
    /// When <c>true</c>, <c>xades:CertDigest/ds:DigestMethod</c> must be SHA-256 (SHA-384 CertDigest is rejected even if the digest value matches).
    /// </summary>
    public bool RestrictSigningCertificateDigestToSha256 { get; init; }

    /// <summary>
    /// When <c>true</c>, the signature must contain at least one non-empty <c>xades:ClaimedRole</c> (after trim).
    /// </summary>
    public bool RequireAtLeastOneSignerClaimedRole { get; init; }

    /// <summary>
    /// When non-empty, every non-empty claimed role must be present in this collection (exact match after trim; ordinal comparison).
    /// Roles declared in XML but empty after trim are ignored. Missing element or all-empty roles do not violate the allow list unless
    /// <see cref="RequireAtLeastOneSignerClaimedRole"/> is <c>true</c>.
    /// </summary>
    public IReadOnlyCollection<string>? SignerClaimedRoleAllowList { get; init; }

    /// <summary>
    /// <c>true</c> when <see cref="RequireAtLeastOneSignerClaimedRole"/> is set or <see cref="SignerClaimedRoleAllowList"/> contains a non-whitespace entry.
    /// </summary>
    public bool HasSignerClaimedRoleConstraints
    {
        get
        {
            if (RequireAtLeastOneSignerClaimedRole)
            {
                return true;
            }

            if (SignerClaimedRoleAllowList is null)
            {
                return false;
            }

            foreach (var s in SignerClaimedRoleAllowList)
            {
                if (!string.IsNullOrWhiteSpace(s))
                {
                    return true;
                }
            }

            return false;
        }
    }

    /// <summary>
    /// Optional check that an embedded XAdES-T <c>SignatureTimeStamp</c> token matches <c>SignatureValue</c> (not archive timestamps).
    /// Default <see cref="SignatureTimestampImprintPolicy.RequireWhenPresent"/> for greenfield validation.
    /// </summary>
    public SignatureTimestampImprintPolicy TimestampImprintPolicy { get; init; } = SignatureTimestampImprintPolicy.RequireWhenPresent;

    /// <summary>
    /// When an encapsulated RFC 3161 token is present, verify the TSA certificate (time-stamp EKU) and CMS
    /// <c>SignerInformation.Verify</c>. Requires the TSA certificate inside the token’s certificate set (typical for public TSPs).
    /// </summary>
    public bool ValidateTsaSigner { get; init; }

    /// <summary>
    /// After TSA CMS verification, build a PKIX chain for the TSA certificate (implies the same checks as <see cref="ValidateTsaSigner"/>).
    /// Trust roots: <see cref="TsaTrustAnchors"/> when non-empty; otherwise <see cref="CustomTrustAnchors"/> when non-empty; otherwise the OS trust store.
    /// </summary>
    public bool ValidateTsaSignerChain { get; init; }

    /// <summary>
    /// Optional roots used only for the TSA PKIX chain when <see cref="ValidateTsaSignerChain"/> is <c>true</c>.
    /// When <c>null</c> or empty, falls back to <see cref="CustomTrustAnchors"/>.
    /// </summary>
    public X509Certificate2Collection? TsaTrustAnchors { get; init; }

    /// <summary>
    /// When <c>true</c> and <see cref="TrustedListServiceIndex"/> is configured, timestamp validation fails unless the
    /// TSA certificate from <c>xades:SignatureTimeStamp</c> is listed in the trusted list.
    /// </summary>
    /// <remarks>
    /// Setting this flag forces CMS verification of the TSA token (equivalent to setting <see cref="ValidateTsaSigner"/>);
    /// a TSL listing match on a token whose CMS signature was never verified would be exploitable.
    /// </remarks>
    public bool RequireTimestampAuthorityCertificateListedInTrustedList { get; init; }

    /// <summary>
    /// When <c>true</c> together with <see cref="RequireTimestampAuthorityCertificateListedInTrustedList"/> and a configured
    /// <see cref="TrustedListServiceIndex"/>, the matching TSA trusted-list service must also map to a granted-like status URI.
    /// </summary>
    /// <remarks>
    /// Setting this flag forces CMS verification of the TSA token (equivalent to setting <see cref="ValidateTsaSigner"/>).
    /// </remarks>
    public bool RequireTimestampAuthorityServiceStatusGranted { get; init; }

    /// <summary>
    /// When <c>true</c> and <see cref="TrustedListServiceIndex"/> is configured, the matched TSA TSL service-type must be a
    /// qualified time-stamping service (eIDAS Article 42 / ETSI <c>TSA/QTST</c>) according to
    /// <see cref="TslQualificationIndicators.SuggestsQualifiedTimestampService"/>. Non-qualified <c>TSA</c> service entries fail.
    /// Implies <see cref="RequireTimestampAuthorityCertificateListedInTrustedList"/> for the TSL lookup; combine with
    /// <see cref="RequireTimestampAuthorityServiceStatusGranted"/> for the full eIDAS Art. 42 conformant gate.
    /// </summary>
    /// <remarks>
    /// Required to fulfil the EDOC 2.0 LV LTV clause "kvalificēts laika zīmogs" (qualified time-stamp). Hosts targeting other
    /// jurisdictions should enable this whenever the published trust list distinguishes qualified TSAs from generic TSAs.
    /// Setting this flag forces CMS verification of the TSA token (equivalent to setting <see cref="ValidateTsaSigner"/>).
    /// </remarks>
    public bool RequireQualifiedTimestampServiceType { get; init; }
}
