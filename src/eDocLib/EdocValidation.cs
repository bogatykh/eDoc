using System.Collections.Generic;
using System.IO;
using System.Linq;
using eDocLib.Configuration;
using eDocLib.Validation;
using eDocLib.Validation.Reporting;
using eDocLib.Asic.Xades;

namespace eDocLib;

/// <summary>
/// Signature verification for loaded <see cref="Edoc"/> instances. For open+validate in one step use
/// <see cref="Edoc.OpenAndValidate(eDocLib.Configuration.EdocLibConfig, System.IO.Stream, SignatureTrustPolicy?)"/> or this type’s
/// <see cref="OpenAndValidate(Stream, SignatureTrustPolicy?)"/> (uses <see cref="EdocLibConfig.Default"/> read profile).
/// </summary>
public static class EdocValidation
{
    /// <summary>
    /// Opens with <see cref="EdocLibConfig.Default"/> read settings, then verifies each signature.
    /// For custom spill paths or thresholds, use <c>Edoc.OpenAndValidate(EdocLibConfigBuilder.Create().WithPayloadSpillTempDirectory(...).WithPayloadMemoryThresholdBytes(...).Build(), stream, policy)</c>.
    /// </summary>
    public static EdocReadValidationResult OpenAndValidate(Stream stream, SignatureTrustPolicy? trustPolicy = null) =>
        Edoc.OpenAndValidate(EdocLibConfig.Default, stream, trustPolicy);

    /// <summary>
    /// Verifies each signature on an already-loaded <see cref="Edoc"/> (no container I/O).
    /// Use when signatures are attached in memory as custom <see cref="ISignature"/> implementations (not produced by this library’s signing jobs).
    /// </summary>
    public static EdocReadValidationResult ValidateSignatures(Edoc edoc, SignatureTrustPolicy? trustPolicy = null)
    {
        ArgumentNullException.ThrowIfNull(edoc);
        trustPolicy ??= SignatureTrustPolicy.CryptographyOnly;

        var payloads = BuildPayloadDictionary(edoc);
        var list = new List<EdocSignatureVerification>(edoc.Signatures.Count);
        var index = 0;
        foreach (var sig in edoc.Signatures)
        {
            SignatureValidationResult result;
            if (sig is XadesSignature xs)
            {
                result = SignatureValidator.Validate(xs, payloads, trustPolicy);
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

    /// <summary>Builds validation report.</summary>
    public static DocumentValidationReport BuildValidationReport(this EdocReadValidationResult result, SignatureTrustPolicy policy) =>
        BuildValidationReport(result, policy, reportOptions: null);

    /// <summary>Builds validation report.</summary>
    public static DocumentValidationReport BuildValidationReport(
        this EdocReadValidationResult result,
        SignatureTrustPolicy policy,
        ValidationReportOptions? reportOptions)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(policy);
        return ValidationReportFactory.CreateDocumentReport(result, policy, reportOptions);
    }

    /// <summary>Same as the overload on <see cref="EdocReadValidationResult"/> when the aggregate result is only known through <see cref="IEdocContainerValidationResult"/>.</summary>
    public static DocumentValidationReport BuildValidationReport(this IEdocContainerValidationResult result, SignatureTrustPolicy policy) =>
        BuildValidationReport(result, policy, reportOptions: null);

    /// <summary>Builds a validation report.</summary>
    /// <inheritdoc cref="BuildValidationReport(EdocReadValidationResult, SignatureTrustPolicy, ValidationReportOptions?)"/>
    public static DocumentValidationReport BuildValidationReport(
        this IEdocContainerValidationResult result,
        SignatureTrustPolicy policy,
        ValidationReportOptions? reportOptions)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(policy);
        return ValidationReportFactory.CreateDocumentReport(result, policy, reportOptions);
    }

    /// <summary>Builds payload dictionary.</summary>
    private static Dictionary<string, byte[]> BuildPayloadDictionary(Edoc edoc)
    {
        var dict = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var df in edoc.DataFiles)
        {
            if (df.Stream.CanSeek)
            {
                df.Stream.Position = 0;
            }

            using var ms = new MemoryStream();
            df.Stream.CopyTo(ms);
            if (df.Stream.CanSeek)
            {
                df.Stream.Position = 0;
            }

            dict[df.Name] = ms.ToArray();
        }

        return dict;
    }
}

/// <summary>Outcome of <see cref="Edoc.OpenAndValidate(eDocLib.Configuration.EdocLibConfig, System.IO.Stream, eDocLib.Validation.SignatureTrustPolicy?)"/>.</summary>
public sealed class EdocReadValidationResult : IEdocContainerValidationResult
{
    /// <summary>Gets or sets the eDoc.</summary>
    /// <inheritdoc />
    public required Edoc Edoc { get; init; }

    /// <summary>Gets or sets the signatures.</summary>
    /// <inheritdoc />
    public required IReadOnlyList<EdocSignatureVerification> Signatures { get; init; }

    /// <summary>Stores the has signatures.</summary>
    /// <inheritdoc />
    public bool HasSignatures => Signatures.Count > 0;

    /// <summary>Stores the all signatures valid.</summary>
    /// <inheritdoc />
    public bool AllSignaturesValid => HasSignatures && Signatures.All(s => s.Result.Success);

    /// <summary>Stores the has warnings.</summary>
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
