using System.Collections.Generic;
using eDocLib;
using eDocLib.Asic.Xades;

namespace eDocLib.Validation;

/// <summary>
/// Verifies every detached signature on a loaded <see cref="Edoc"/> (no container I/O).
/// Use <see cref="Default"/> from application code; <see cref="EdocValidation"/> forwards here for convenience overloads.
/// </summary>
public sealed class EdocContainerSignatureValidator
{
    /// <summary>Shared stateless instance.</summary>
    public static EdocContainerSignatureValidator Default { get; } = new();

    private EdocContainerSignatureValidator()
    {
    }

    /// <summary>
    /// Verifies each signature on <paramref name="edoc"/> using <paramref name="trustPolicy"/> (defaults to <see cref="SignatureTrustPolicy.CryptographyOnly"/>).
    /// </summary>
    public async Task<EdocReadValidationResult> ValidateSignaturesAsync(
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
            cancellationToken.ThrowIfCancellationRequested();
            SignatureValidationResult result;
            if (sig is XadesSignature xs)
            {
                result = await SignatureValidator.ValidateAsync(xs, payloadSource, trustPolicy, cancellationToken)
                    .ConfigureAwait(false);
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
}
