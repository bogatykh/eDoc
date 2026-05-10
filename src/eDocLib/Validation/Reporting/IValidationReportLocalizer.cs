using System.Globalization;
using eDocLib.Validation;

namespace eDocLib.Validation.Reporting;

/// <summary>Supplies localized or application-defined strings for validation reporting.</summary>
public interface IValidationReportLocalizer
{
    /// <summary>Culture used by the localizer, or <c>null</c> for the current UI culture.</summary>
    CultureInfo? Culture { get; }

    /// <summary>Returns a display string for a signature validation indication.</summary>
    string Indication(SignatureValidationIndication indication);

    /// <summary>Returns a display string for a validation status.</summary>
    string DescribeValidationStatus(ValidationStatus status);

    /// <summary>Returns a caption for a validation node type.</summary>
    string ValidationTypeCaption(ValidationType type);

    /// <summary>Returns a display string for a signature profile.</summary>
    string DescribeSignatureProfile(SignatureProfile profile);

    /// <summary>Returns a display string for a signature qualification.</summary>
    string DescribeSignatureQualification(SignatureQualification qualification);

    /// <summary>Returns a display string for a certificate qualification.</summary>
    string DescribeCertificateQualification(CertificateQualification qualification);

    /// <summary>Returns a display string for a timestamp qualification.</summary>
    string DescribeTimestampQualification(TimestampQualification qualification);

    /// <summary>Returns a display string for a validation signature type.</summary>
    string DescribeValidationSignatureType(ValidationSignatureType type);

    /// <summary>Returns an optional legal-basis hint for a validation indication.</summary>
    string? LegalBasisHint(SignatureValidationIndication indication);
}
