using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using eDocLib;
using eDocLib.Revocation;
using eDocLib.Revocation.Online;

namespace eDocLib.Validation;

/// <summary>
/// Trust options for XML signature validation (chain building and revocation flags passed to <see cref="X509Chain"/>).
/// </summary>
public sealed partial class SignatureTrustPolicy
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
}
