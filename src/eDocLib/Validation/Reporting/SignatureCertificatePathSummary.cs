using eDocLib.Validation;

namespace eDocLib.Validation.Reporting;

/// <summary>
/// PKIX certificate paths produced while validating a signature (signing certificate toward trust anchor; optional TSA path).
/// Names follow path semantics from ITU-T X.509 / RFC 5280 — not a reproduction of third-party validation DTOs.
/// </summary>
public sealed record SignatureCertificatePathSummary(
    IReadOnlyList<CertificateChainDiagnostic>? SigningCertificatePath,
    IReadOnlyList<CertificateChainDiagnostic>? TimeStampAuthorityPath)
{
    /// <summary>Creates a value from signature validation result.</summary>
    public static SignatureCertificatePathSummary FromSignatureValidationResult(SignatureValidationResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        return new SignatureCertificatePathSummary(result.SignerCertificateChain, result.TsaSignerCertificateChain);
    }

    /// <summary>Stores the signing path fully trusted.</summary>
    /// <inheritdoc cref="CertificatePathStatus.AllElementsNoError(IReadOnlyList{CertificateChainDiagnostic}?)"/>
    public bool? SigningPathFullyTrusted => CertificatePathStatus.AllElementsNoError(SigningCertificatePath);

    /// <summary>Stores the time stamp authority path fully trusted.</summary>
    /// <inheritdoc cref="CertificatePathStatus.AllElementsNoError(IReadOnlyList{CertificateChainDiagnostic}?)"/>
    public bool? TimeStampAuthorityPathFullyTrusted =>
        CertificatePathStatus.AllElementsNoError(TimeStampAuthorityPath);
}
