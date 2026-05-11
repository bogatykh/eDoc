using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using eDocLib.Revocation;
using eDocLib.Revocation.Online;
using eDocLib;

namespace eDocLib.Validation;

/// <summary>
/// Trust options for XML signature validation (chain building and revocation flags passed to <see cref="X509Chain"/>).
/// </summary>
public sealed class SignatureTrustPolicy
{
    /// <summary>Only reference digests + RSA over <c>SignedInfo</c> (no PKI path validation).</summary>
    public static SignatureTrustPolicy CryptographyOnly { get; } = new()
    {
        ValidateCertificateChain = false,
    };

    /// <summary>
    /// Cryptographic XML checks plus XAdES-T imprint validation when <c>xades:SignatureTimeStamp</c> / <c>EncapsulatedTimeStamp</c> is embedded (no chain building).
    /// </summary>
    public static SignatureTrustPolicy CryptographyAndTimestampImprint { get; } = new()
    {
        ValidateCertificateChain = false,
        TimestampImprintPolicy = SignatureTimestampImprintPolicy.RequireWhenPresent,
    };

    /// <summary>
    /// Like <see cref="CryptographyAndTimestampImprint"/>, plus CMS verification of the TSA signer on the embedded RFC 3161 token; no PKIX chain for the TSA.
    /// </summary>
    public static SignatureTrustPolicy CryptographyTimestampImprintAndTsaSigner { get; } = new()
    {
        ValidateCertificateChain = false,
        TimestampImprintPolicy = SignatureTimestampImprintPolicy.RequireWhenPresent,
        ValidateTsaSigner = true,
    };

    /// <summary>Build chain to system trust anchors; revocation checks disabled by default.</summary>
    public static SignatureTrustPolicy SystemAnchorsNoRevocation { get; } = new()
    {
        ValidateCertificateChain = true,
        RevocationMode = X509RevocationMode.NoCheck,
    };

    /// <summary>
    /// Recommended baseline for Latvian EDOC 2.0 LTV validation:
    /// cryptographic checks, signer PKIX, XAdES SigningCertificate requirement,
    /// embedded timestamp imprint + TSA CMS/PKIX checks, and embedded unsigned revocation checks.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This baseline keeps revocation mode at <see cref="X509RevocationMode.NoCheck"/> for deterministic offline validation of
    /// embedded LT material. Hosts can override with online revocation by cloning this value in an object initializer.
    /// </para>
    /// <para>
    /// When <paramref name="trustedListServiceIndex"/> is provided, signer and TSA listing checks are enabled together with
    /// <see cref="RequireQualifiedTimestampServiceType"/>: the matched TSA TSL block must be a qualified time-stamping
    /// service (ETSI <c>TSA/QTST</c>) with a granted-equivalent status. That matches the EDOC 2.0 LV clause
    /// "kvalificēts laika zīmogs" (qualified time-stamp) in section 2 of the published profile.
    /// </para>
    /// </remarks>
    public static SignatureTrustPolicy ForLatvianEdocLtv(
        TrustedListServiceIndex? trustedListServiceIndex = null,
        DateTimeOffset? trustedListQualificationReferenceTimeUtc = null) =>
        new()
        {
            ValidateCertificateChain = true,
            RevocationMode = X509RevocationMode.NoCheck,
            RequireXadesSigningCertificate = true,
            TimestampImprintPolicy = SignatureTimestampImprintPolicy.RequireWhenPresent,
            ValidateTsaSigner = true,
            ValidateTsaSignerChain = true,
            VerifyUnsignedRevocationWhenPresent = true,
            TrustedListServiceIndex = trustedListServiceIndex,
            TrustedListQualificationReferenceTimeUtc = trustedListQualificationReferenceTimeUtc,
            RequireSigningCertificateListedInTrustedList = trustedListServiceIndex is not null,
            RequireTrustedListServiceStatusGranted = trustedListServiceIndex is not null,
            RequireTimestampAuthorityCertificateListedInTrustedList = trustedListServiceIndex is not null,
            RequireTimestampAuthorityServiceStatusGranted = trustedListServiceIndex is not null,
            RequireQualifiedTimestampServiceType = trustedListServiceIndex is not null,
            MergeTrustListQualificationUriDefaults = true,
        };

    /// <summary>When <c>true</c>, builds and validates the signer certificate chain.</summary>
    public bool ValidateCertificateChain { get; init; }

    /// <summary>Revocation mode used for PKIX chain builds unless application-controlled online revocation is active.</summary>
    public X509RevocationMode RevocationMode { get; init; } = X509RevocationMode.NoCheck;

    /// <summary>
    /// When set together with <see cref="RevocationMode"/> <see cref="X509RevocationMode.Online"/>, OCSP and CRL are downloaded
    /// from the end-entity certificate’s AIA and CDP using this <see cref="HttpClient"/> after a successful PKIX chain build.
    /// <see cref="X509Chain"/> revocation is forced to <see cref="X509RevocationMode.NoCheck"/> for that build so revocation is not
    /// duplicated by the platform. When <c>null</c>, Online mode uses the default <see cref="X509Chain"/> behaviour only.
    /// </summary>
    public HttpClient? RevocationHttpClient { get; init; }

    /// <summary>
    /// Passed to HTTP revocation fetches when <see cref="RevocationHttpClient"/> is used with <see cref="X509RevocationMode.Online"/>.
    /// </summary>
    public CancellationToken RevocationFetchCancellationToken { get; init; }

    /// <summary>
    /// Time bound for OCSP/CRL HTTP when <see cref="UsesApplicationControlledOnlineRevocation"/> is <c>true</c>.
    /// Use <see cref="Timeout.InfiniteTimeSpan"/> for no wall-clock limit (still honours <see cref="RevocationFetchCancellationToken"/>).
    /// </summary>
    public TimeSpan RevocationFetchTimeout { get; init; } = RevocationFetchLimits.DefaultFetchTimeout;

    /// <summary>Maximum bytes read per revocation HTTP response (OCSP and each CRL attempt).</summary>
    public int RevocationMaxResponseBytes { get; init; } = RevocationFetchLimits.DefaultMaxResponseBytes;

    /// <summary>
    /// When <c>true</c>, revocation URLs whose host is a literal loopback or private IP are rejected before any HTTP request.
    /// Hostnames are not resolved (use a hardened <see cref="HttpClient"/> / handler for stricter SSRF controls).
    /// </summary>
    public bool RevocationRejectLiteralPrivateAndLoopbackHosts { get; init; }

    /// <summary>
    /// Optional cache for OCSP/CRL DER when <see cref="UsesApplicationControlledOnlineRevocation"/> runs.
    /// Use <see cref="DirectoryRevocationDerCache"/> or a custom <see cref="IRevocationDerCache"/> implementation.
    /// </summary>
    public IRevocationDerCache? RevocationDerCache { get; init; }

    /// <summary>
    /// When <c>true</c> with application-controlled online revocation, after a successful base CRL fetch from CDP,
    /// attempts to download a delta CRL from HTTP(S) URIs listed in the base CRL’s Freshest CRL extension (RFC 5280).
    /// A missing extension or unreachable URIs does not fail the fetch (only the base CRL is used).
    /// Default <c>false</c> preserves behaviour prior to this option (base CRL only).
    /// </summary>
    public bool RevocationFetchDeltaCrlViaFreshestCdp { get; init; }

    /// <summary>
    /// <c>true</c> when <see cref="RevocationHttpClient"/> is non-null and <see cref="RevocationMode"/> is
    /// <see cref="X509RevocationMode.Online"/> (application-controlled OCSP/CRL fetch after chain build).
    /// </summary>
    public bool UsesApplicationControlledOnlineRevocation =>
        RevocationHttpClient is not null && RevocationMode == X509RevocationMode.Online;

    /// <summary>
    /// Applies <see cref="RevocationMode"/> to <paramref name="chainPolicy"/>, mapping application-controlled online revocation
    /// to <see cref="X509RevocationMode.NoCheck"/> on the chain (fetch runs separately).
    /// </summary>
    public void ApplyRevocationMode(X509ChainPolicy chainPolicy)
    {
        ArgumentNullException.ThrowIfNull(chainPolicy);
        chainPolicy.RevocationMode = UsesApplicationControlledOnlineRevocation
            ? X509RevocationMode.NoCheck
            : RevocationMode;
    }

    /// <summary>
    /// Creates an <see cref="X509Chain"/> with <see cref="X509RevocationFlag.ExcludeRoot"/> and this policy’s revocation mode
    /// (<see cref="ApplyRevocationMode"/>).
    /// </summary>
    public X509Chain CreateX509Chain()
    {
        var chain = new X509Chain();
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        ApplyRevocationMode(chain.ChainPolicy);
        return chain;
    }

    /// <summary>
    /// Applies <see cref="ExtraChainCertificates"/> (<c>ExtraStore</c>) and <see cref="CustomTrustAnchors"/> to <paramref name="chainPolicy"/>
    /// for PKIX validation of the XML-DSig signer certificate (see <see cref="ValidateCertificateChain"/>).
    /// </summary>
    public void ApplySignerChainStores(X509ChainPolicy chainPolicy)
    {
        ArgumentNullException.ThrowIfNull(chainPolicy);
        X509ChainBuildHelpers.ApplyExtraStoreAndTrustAnchors(chainPolicy, ExtraChainCertificates, CustomTrustAnchors);
    }

    /// <summary>
    /// Applies trust roots for TSA PKIX validation: <see cref="TsaTrustAnchors"/> when non-empty; otherwise <see cref="CustomTrustAnchors"/>.
    /// </summary>
    public void ApplyTsaChainTrustAnchors(X509ChainPolicy chainPolicy)
    {
        ArgumentNullException.ThrowIfNull(chainPolicy);
        var roots = TsaTrustAnchors is { Count: > 0 } ? TsaTrustAnchors : CustomTrustAnchors;
        X509ChainBuildHelpers.ApplyTrustAnchors(chainPolicy, roots);
    }

    /// <summary>
    /// Validates <see cref="RevocationFetchTimeout"/> / <see cref="RevocationMaxResponseBytes"/> when application-controlled
    /// online revocation is active. Call before issuing HTTP requests.
    /// </summary>
    /// <exception cref="InvalidOperationException">Policy fields are inconsistent or out of range.</exception>
    public void ValidateRevocationFetchConfiguration()
    {
        if (!UsesApplicationControlledOnlineRevocation)
        {
            return;
        }

        if (RevocationMaxResponseBytes <= 0)
        {
            throw new InvalidOperationException($"{nameof(RevocationMaxResponseBytes)} must be positive.");
        }

        if (RevocationFetchTimeout < TimeSpan.Zero && RevocationFetchTimeout != Timeout.InfiniteTimeSpan)
        {
            throw new InvalidOperationException($"{nameof(RevocationFetchTimeout)} cannot be negative.");
        }

        if (RevocationFetchTimeout == TimeSpan.Zero)
        {
            throw new InvalidOperationException(
                $"{nameof(RevocationFetchTimeout)} cannot be zero; use {nameof(Timeout)}.{nameof(Timeout.InfiniteTimeSpan)} for no time limit.");
        }
    }

    /// <summary>
    /// When non-empty, chain policy uses <see cref="X509ChainTrustMode.CustomRootTrust"/> with these roots
    /// (e.g. self-signed test CAs or national trust bundles managed by the host app).
    /// </summary>
    public X509Certificate2Collection? CustomTrustAnchors { get; init; }

    /// <summary>
    /// Additional certificates passed to chain policy <c>ExtraStore</c> when building the signer chain
    /// (e.g. CA / QC intermediates taken from a national TSL). The same collection is also consulted when verifying embedded or
    /// fetched CRL signatures if the CRL issuer certificate is not on the established PKIX path (delegated CRL signer). Empty or <c>null</c> is ignored.
    /// </summary>
    public X509Certificate2Collection? ExtraChainCertificates { get; init; }

    /// <summary>
    /// When <see cref="ValidateCertificateChain"/> is <c>true</c>, adds certificates from unsigned XAdES
    /// <c>CertificateValues</c> (<c>EncapsulatedX509Certificate</c> DER and certificates imported from PKCS#7
    /// <c>EncapsulatedPKIData</c>) to chain policy <c>ExtraStore</c> before building the signer PKIX chain.
    /// </summary>
    public bool IncludeUnsignedCertificateValuesInSignerChain { get; init; } = true;

    /// <summary>
    /// Optional index of <c>TSPService/ServiceInformation</c> entries (e.g. from parsing a trusted list XML into a
    /// <see cref="TrustedListServiceIndex"/>). When set, validation records qualification metadata
    /// and can require the signing certificate to appear in the list.
    /// </summary>
    public TrustedListServiceIndex? TrustedListServiceIndex { get; init; }

    /// <summary>
    /// When set together with <see cref="TrustedListServiceIndex"/>, TSL service type and status for qualification mapping use the
    /// <see cref="TrustedListQualification.ServiceHistory"/> segment active at this UTC instant (ETSI TS 119 612).
    /// When <c>null</c>, only current <c>ServiceInformation</c> on the index entry applies.
    /// </summary>
    public DateTimeOffset? TrustedListQualificationReferenceTimeUtc { get; init; }

    /// <summary>Optional extra TSL status / service-type URIs merged into qualification mapping (national lists).</summary>
    public TslQualificationMappingOptions? TslQualificationMappingOptions { get; init; }

    /// <summary>
    /// When <c>true</c> (default), merges built-in national URI additions for Latvia into
    /// <see cref="TslQualificationMappingOptions"/> before qualification mapping (additive URI unions).
    /// Set <c>false</c> to use only explicit options and the core ETSI URI sets from mapping options.
    /// </summary>
    /// <remarks>
    /// This flag exists for historical reasons: the Latvian national TSL publishes ETSI <c>accredited</c>
    /// alongside <c>granted</c> / <c>recognisedatnationallevel</c>, and early integrators relied on the
    /// library merging that mapping silently. Hosts deploying to other jurisdictions should set this to
    /// <c>false</c> and pass an explicit <see cref="TslQualificationMappingOptions"/> with the URI sets
    /// applicable to their territory; rely on this flag only for Latvian deployments.
    /// </remarks>
    public bool MergeTrustListQualificationUriDefaults { get; init; } = true;

    /// <summary>
    /// Resolves the effective <see cref="TslQualificationMappingOptions"/> for this policy: merges the
    /// optional national defaults gated by <see cref="MergeTrustListQualificationUriDefaults"/> with any
    /// caller-supplied <see cref="TslQualificationMappingOptions"/>. Returns <c>null</c> when there is
    /// nothing to merge (no defaults requested and no caller options).
    /// </summary>
    /// <remarks>
    /// The validator calls this rather than reaching into territory-specific defaults from inside the
    /// generic verification engine, so the host-visible policy is the single point that decides whether
    /// a national mapping bundle is merged in.
    /// </remarks>
    internal TslQualificationMappingOptions? ResolveQualificationMappingOptions()
    {
        if (!MergeTrustListQualificationUriDefaults)
        {
            return TslQualificationMappingOptions;
        }

        return TslQualificationMappingOptions.Merge(
            TslQualificationMappingDefaults.LatvianNationalPublished,
            TslQualificationMappingOptions)
            ?? TslQualificationMappingDefaults.LatvianNationalPublished;
    }

    /// <summary>
    /// When <c>true</c> and <see cref="TrustedListServiceIndex"/> is non-null, validation fails if the signing certificate
    /// is missing or not listed under any <c>ServiceInformation</c> block.
    /// </summary>
    public bool RequireSigningCertificateListedInTrustedList { get; init; }

    /// <summary>
    /// When <c>true</c> and <see cref="TrustedListServiceIndex"/> is non-null, the signer must be listed and the TSL
    /// <c>ServiceStatus</c> must be one of the granted-like URIs recognised by the configured qualification mapping.
    /// </summary>
    public bool RequireTrustedListServiceStatusGranted { get; init; }

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
