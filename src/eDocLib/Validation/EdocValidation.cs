using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using eDocLib;
using eDocLib.Configuration;
using eDocLib.Validation.Reporting;

namespace eDocLib.Validation;

/// <summary>
/// Convenience entry points for signature verification. Core logic lives on <see cref="EdocContainerSignatureValidator"/>.
/// For open+validate in one step use <see cref="Edoc.OpenAndValidateAsync(EdocLibConfig, Stream, HttpClient, DateTimeOffset?, bool, CancellationToken)"/>
/// (Latvia national TSL + LTV gates; you supply <see cref="HttpClient"/>) or
/// <see cref="Edoc.OpenAndValidateAsync(EdocLibConfig, Stream, SignatureTrustPolicy, CancellationToken)"/> with an explicit <see cref="SignatureTrustPolicy"/>.
/// </summary>
public static class EdocValidation
{
    /// <summary>
    /// Opens with <see cref="EdocLibConfig.Default"/>, fetches the Latvia national TSL using <paramref name="tslHttpClient"/>,
    /// then validates with <see cref="SignatureTrustPolicy.ForLatvianEdocLtvWithDefaultTrustedListAsync"/>.
    /// </summary>
    public static Task<EdocReadValidationResult> OpenAndValidateAsync(
        Stream stream,
        HttpClient tslHttpClient,
        DateTimeOffset? trustedListQualificationReferenceTimeUtc = null,
        bool verifyTrustedListXmlSignature = true,
        CancellationToken cancellationToken = default) =>
        Edoc.OpenAndValidateAsync(
            EdocLibConfig.Default,
            stream,
            tslHttpClient,
            trustedListQualificationReferenceTimeUtc,
            verifyTrustedListXmlSignature,
            cancellationToken);

    /// <summary>
    /// Opens with <see cref="EdocLibConfig.Default"/> read settings, then verifies each signature using <paramref name="trustPolicy"/>.
    /// For custom spill paths or thresholds, use <c>Edoc.OpenAndValidateAsync(EdocLibConfigBuilder.Create().WithPayloadSpillTempDirectory(...).WithPayloadMemoryThresholdBytes(...).Build(), stream, trustPolicy)</c>.
    /// </summary>
    public static Task<EdocReadValidationResult> OpenAndValidateAsync(
        Stream stream,
        SignatureTrustPolicy trustPolicy,
        CancellationToken cancellationToken = default) =>
        Edoc.OpenAndValidateAsync(EdocLibConfig.Default, stream, trustPolicy, cancellationToken);

    /// <inheritdoc cref="Edoc.OpenAndValidateAsync(EdocLibConfig, Stream, HttpClient, DateTimeOffset?, bool, CancellationToken)"/>
    public static Task<EdocReadValidationResult> OpenAndValidateAsync(
        EdocLibConfig config,
        Stream stream,
        HttpClient tslHttpClient,
        DateTimeOffset? trustedListQualificationReferenceTimeUtc = null,
        bool verifyTrustedListXmlSignature = true,
        CancellationToken cancellationToken = default) =>
        Edoc.OpenAndValidateAsync(
            config,
            stream,
            tslHttpClient,
            trustedListQualificationReferenceTimeUtc,
            verifyTrustedListXmlSignature,
            cancellationToken);

    /// <inheritdoc cref="Edoc.OpenAndValidateAsync(EdocLibConfig, Stream, SignatureTrustPolicy, CancellationToken)"/>
    public static Task<EdocReadValidationResult> OpenAndValidateAsync(
        EdocLibConfig config,
        Stream stream,
        SignatureTrustPolicy trustPolicy,
        CancellationToken cancellationToken = default) =>
        Edoc.OpenAndValidateAsync(config, stream, trustPolicy, cancellationToken);

    /// <summary>
    /// Validates an opened container after resolving <see cref="SignatureTrustPolicy.ForLatvianEdocLtvWithDefaultTrustedListAsync"/> (TSL fetch).
    /// </summary>
    public static async Task<EdocReadValidationResult> ValidateLatvianLtvAsync(
        Edoc edoc,
        EdocLibConfig config,
        HttpClient tslHttpClient,
        DateTimeOffset? trustedListQualificationReferenceTimeUtc = null,
        bool verifyTrustedListXmlSignature = true,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(edoc);
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(tslHttpClient);

        var policy = await SignatureTrustPolicy.ForLatvianEdocLtvWithDefaultTrustedListAsync(
                config,
                tslHttpClient,
                trustedListQualificationReferenceTimeUtc,
                verifyTrustedListXmlSignature,
                cancellationToken)
            .ConfigureAwait(false);

        return await ValidateSignaturesAsync(edoc, policy, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc cref="ValidateLatvianLtvAsync(Edoc, EdocLibConfig, HttpClient, DateTimeOffset?, bool, CancellationToken)"/>
    public static Task<EdocReadValidationResult> ValidateLatvianLtvAsync(
        Edoc edoc,
        HttpClient tslHttpClient,
        DateTimeOffset? trustedListQualificationReferenceTimeUtc = null,
        bool verifyTrustedListXmlSignature = true,
        CancellationToken cancellationToken = default) =>
        ValidateLatvianLtvAsync(
            edoc,
            EdocLibConfig.Default,
            tslHttpClient,
            trustedListQualificationReferenceTimeUtc,
            verifyTrustedListXmlSignature,
            cancellationToken);

    /// <summary>
    /// Verifies each signature on an already-loaded <see cref="Edoc"/> (no container I/O).
    /// Use when signatures are attached in memory as custom <see cref="ISignature"/> implementations (not produced by this library’s signing jobs).
    /// </summary>
    public static Task<EdocReadValidationResult> ValidateSignaturesAsync(
        Edoc edoc,
        SignatureTrustPolicy? trustPolicy = null,
        CancellationToken cancellationToken = default) =>
        EdocContainerSignatureValidator.Default.ValidateSignaturesAsync(edoc, trustPolicy, cancellationToken);

    /// <summary>Delegates to <see cref="EdocContainerValidationReportExtensions.BuildValidationReport(EdocReadValidationResult, SignatureTrustPolicy)"/>.</summary>
    public static DocumentValidationReport BuildValidationReport(EdocReadValidationResult result, SignatureTrustPolicy policy) =>
        result.BuildValidationReport(policy);

    /// <summary>Delegates to <see cref="EdocContainerValidationReportExtensions.BuildValidationReport(EdocReadValidationResult, SignatureTrustPolicy, ValidationReportOptions?)"/>.</summary>
    public static DocumentValidationReport BuildValidationReport(
        EdocReadValidationResult result,
        SignatureTrustPolicy policy,
        ValidationReportOptions? reportOptions) =>
        result.BuildValidationReport(policy, reportOptions);

    /// <summary>Delegates to <see cref="EdocContainerValidationReportExtensions.BuildValidationReport(IEdocContainerValidationResult, SignatureTrustPolicy)"/>.</summary>
    public static DocumentValidationReport BuildValidationReport(IEdocContainerValidationResult result, SignatureTrustPolicy policy) =>
        result.BuildValidationReport(policy);

    /// <summary>Delegates to <see cref="EdocContainerValidationReportExtensions.BuildValidationReport(IEdocContainerValidationResult, SignatureTrustPolicy, ValidationReportOptions?)"/>.</summary>
    public static DocumentValidationReport BuildValidationReport(
        IEdocContainerValidationResult result,
        SignatureTrustPolicy policy,
        ValidationReportOptions? reportOptions) =>
        result.BuildValidationReport(policy, reportOptions);
}
