using System.Collections.Generic;

namespace eDocLib.Validation;

/// <summary>Outcome of <see cref="SignatureTimestampVerifier.TryVerifyTimeStampTokenDerAsync"/>.</summary>
/// <param name="Ok">Whether the policy-driven verification succeeded.</param>
/// <param name="Error">Human-readable primary error when <see cref="Ok"/> is <c>false</c>.</param>
/// <param name="CmsValid">CMS verification outcome of the TSA signer (only when policy requested it).</param>
/// <param name="ChainValid">PKIX chain outcome for the TSA certificate (only when policy requested chain validation).</param>
/// <param name="CertificateChain">TSA certificate chain diagnostic, when chain validation ran.</param>
/// <param name="Tsl">Matched TSA trusted-list metadata when <see cref="SignatureTrustPolicy.TrustedListServiceIndex"/> was queried.</param>
internal readonly record struct TimeStampTokenDerVerifyResult(
    bool Ok,
    string? Error,
    bool? CmsValid,
    bool? ChainValid,
    IReadOnlyList<CertificateChainDiagnostic>? CertificateChain,
    TimestampAuthorityTrustedListEvaluation? Tsl)
{
    public static TimeStampTokenDerVerifyResult Success(
        bool? cmsValid,
        bool? chainValid,
        IReadOnlyList<CertificateChainDiagnostic>? chain,
        TimestampAuthorityTrustedListEvaluation? tsl = null) =>
        new(true, null, cmsValid, chainValid, chain, tsl);

    public static TimeStampTokenDerVerifyResult Fail(
        string error,
        bool? cmsValid,
        bool? chainValid,
        IReadOnlyList<CertificateChainDiagnostic>? chain,
        TimestampAuthorityTrustedListEvaluation? tsl = null) =>
        new(false, error, cmsValid, chainValid, chain, tsl);
}

/// <summary>Snapshot of TSA-specific trusted-list lookup results for downstream reporting.</summary>
/// <param name="Listed">
/// Whether the TSA certificate was found in <see cref="SignatureTrustPolicy.TrustedListServiceIndex"/>.
/// <c>null</c> when no index was configured.
/// </param>
/// <param name="ServiceTypeIdentifiers">Service type URIs from the matched TSL block.</param>
/// <param name="ServiceStatusUri">Service status URI from the matched TSL block.</param>
/// <param name="Indicators">Mapped TSL indicators (qualified-TSA detection, granted status).</param>
internal readonly record struct TimestampAuthorityTrustedListEvaluation(
    bool? Listed,
    IReadOnlyList<string>? ServiceTypeIdentifiers,
    string? ServiceStatusUri,
    TslQualificationIndicators? Indicators);
