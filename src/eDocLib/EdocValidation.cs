using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using eDocLib.Configuration;
using eDocLib.Validation;
using eDocLib.Validation.Reporting;
using eDocLib.Asic.Xades;

namespace eDocLib;

/// <summary>
/// Signature verification for loaded <see cref="Edoc"/> instances. For open+validate in one step use
/// <see cref="Edoc.OpenAndValidateAsync(eDocLib.Configuration.EdocLibConfig, System.IO.Stream, SignatureTrustPolicy?, System.Threading.CancellationToken)"/> or this type’s
/// <see cref="OpenAndValidateAsync(Stream, SignatureTrustPolicy?, CancellationToken)"/> (uses <see cref="EdocLibConfig.Default"/> read profile).
/// </summary>
public static class EdocValidation
{
    /// <summary>
    /// Opens with <see cref="EdocLibConfig.Default"/> read settings, then verifies each signature.
    /// For custom spill paths or thresholds, use <c>Edoc.OpenAndValidateAsync(EdocLibConfigBuilder.Create().WithPayloadSpillTempDirectory(...).WithPayloadMemoryThresholdBytes(...).Build(), stream, policy)</c>.
    /// </summary>
    public static Task<EdocReadValidationResult> OpenAndValidateAsync(
        Stream stream,
        SignatureTrustPolicy? trustPolicy = null,
        CancellationToken cancellationToken = default) =>
        Edoc.OpenAndValidateAsync(EdocLibConfig.Default, stream, trustPolicy, cancellationToken);

    /// <summary>
    /// Verifies each signature on an already-loaded <see cref="Edoc"/> (no container I/O).
    /// Use when signatures are attached in memory as custom <see cref="ISignature"/> implementations (not produced by this library’s signing jobs).
    /// </summary>
    public static async Task<EdocReadValidationResult> ValidateSignaturesAsync(
        Edoc edoc,
        SignatureTrustPolicy? trustPolicy = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(edoc);
        cancellationToken.ThrowIfCancellationRequested();
        trustPolicy ??= SignatureTrustPolicy.CryptographyOnly;

        var payloadSource = new EdocDataFilePayloadSource(edoc);
        var list = new List<EdocSignatureVerification>(edoc.Signatures.Count);
        var index = 0;
        foreach (var sig in edoc.Signatures)
        {
            // Observe cancellation between signatures so a pre-cancelled token or one cancelled mid-loop
            // stops iteration without depending on the downstream validator hitting an async checkpoint
            // (synchronous CryptographyOnly path on self-signed certs has none).
            cancellationToken.ThrowIfCancellationRequested();
            SignatureValidationResult result;
            if (sig is XadesSignature xs)
            {
                result = await SignatureValidator.ValidateAsync(xs, payloadSource, trustPolicy, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                result = new SignatureValidationResult
                {
                    Success = false,
                    Error = "This signature type does not support XML-DSig / XAdES verification in this library.",
                    ReferencesAndSignatureValid = false,
                    CertificateChainValid = trustPolicy.ValidateCertificateChain ? false : null,
                };
            }

            list.Add(new EdocSignatureVerification
            {
                Ordinal = index++,
                Signature = sig,
                Result = result,
            });
        }

        return new EdocReadValidationResult
        {
            Edoc = edoc,
            Signatures = list,
        };
    }

    /// <inheritdoc cref="BuildValidationReport(EdocReadValidationResult, SignatureTrustPolicy, ValidationReportOptions?)"/>
    public static DocumentValidationReport BuildValidationReport(this EdocReadValidationResult result, SignatureTrustPolicy policy) =>
        BuildValidationReport(result, policy, reportOptions: null);

    /// <summary>Builds a validation report for the opened container and each signature row. Use <see cref="ValidationReportOptions"/> for reference time and optional tree/summary strings (<see cref="ValidationReportOptions.ReportLocalizer"/>).</summary>
    public static DocumentValidationReport BuildValidationReport(
        this EdocReadValidationResult result,
        SignatureTrustPolicy policy,
        ValidationReportOptions? reportOptions)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(policy);
        return ValidationReportFactory.CreateDocumentReport(result, policy, reportOptions);
    }

    /// <inheritdoc cref="BuildValidationReport(IEdocContainerValidationResult, SignatureTrustPolicy, ValidationReportOptions?)"/>
    public static DocumentValidationReport BuildValidationReport(this IEdocContainerValidationResult result, SignatureTrustPolicy policy) =>
        BuildValidationReport(result, policy, reportOptions: null);

    /// <summary>Builds a validation report when the outcome is exposed as <see cref="IEdocContainerValidationResult"/> (see <see cref="ValidationReportOptions"/>).</summary>
    public static DocumentValidationReport BuildValidationReport(
        this IEdocContainerValidationResult result,
        SignatureTrustPolicy policy,
        ValidationReportOptions? reportOptions)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(policy);
        return ValidationReportFactory.CreateDocumentReport(result, policy, reportOptions);
    }

}

/// <summary>Outcome of <see cref="Edoc.OpenAndValidateAsync(eDocLib.Configuration.EdocLibConfig, System.IO.Stream, eDocLib.Validation.SignatureTrustPolicy?, System.Threading.CancellationToken)"/>.</summary>
public sealed class EdocReadValidationResult : IEdocContainerValidationResult
{
    /// <inheritdoc />
    public required Edoc Edoc { get; init; }

    /// <inheritdoc />
    public required IReadOnlyList<EdocSignatureVerification> Signatures { get; init; }

    /// <inheritdoc />
    public bool HasSignatures => Signatures.Count > 0;

    /// <inheritdoc />
    public bool AllSignaturesValid => HasSignatures && Signatures.All(s => s.Result.Success);

    /// <inheritdoc />
    public bool HasWarnings =>
        Signatures.Any(static s =>
            s.Result.GetIndication() == SignatureValidationIndication.Indeterminate);
}

/// <summary>One container signature and its validation outcome.</summary>
public sealed class EdocSignatureVerification
{
    /// <summary>Zero-based signature position in the container.</summary>
    public required int Ordinal { get; init; }

    /// <summary>Signature object that was validated.</summary>
    public required ISignature Signature { get; init; }

    /// <summary>Validation result for the signature.</summary>
    public required SignatureValidationResult Result { get; init; }
}
