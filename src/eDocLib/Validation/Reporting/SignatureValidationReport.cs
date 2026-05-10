using eDocLib.Validation;

namespace eDocLib.Validation.Reporting;

/// <summary>Structured validation report for one signature, including qualification hints and the raw validator output.</summary>
public sealed record SignatureValidationReport(
    int Ordinal,
    ValidationSignatureType ValidationSignatureType,
    SignatureProfile SignatureProfile,
    SignatureQualification SignatureQualification,
    CertificateQualification SignerCertificateQualification,
    TimestampQualification TimestampQualification,
    SignatureValidationIndication Indication,
    ValidationResultNode Tree,
    SignatureValidationResult RawResult,
    SignatureCertificatePathSummary CertificatePaths)
{
    /// <summary>Short plain-text summary line block for this signature (optional custom <see cref="IValidationReportLocalizer"/>).</summary>
    public string ToSummaryPlainText(IValidationReportLocalizer? localizer = null) =>
        ValidationReportTextFormatter.FormatSignatureSummary(this, localizer);
}
