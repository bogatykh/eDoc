using System.Globalization;
using eDocLib.Validation;

namespace eDocLib.Validation.Reporting;

/// <summary>English defaults for <see cref="IValidationReportLocalizer"/>.</summary>
internal sealed class DefaultValidationReportLocalizer : IValidationReportLocalizer
{
    /// <summary>Initializes a new default validation report localizer instance.</summary>
    public DefaultValidationReportLocalizer(CultureInfo? culture = null) => Culture = culture;

    /// <summary>Gets the culture.</summary>
    public CultureInfo? Culture { get; }

    /// <summary>Returns the validation indication text.</summary>
    public string Indication(SignatureValidationIndication indication) =>
        indication switch
        {
            SignatureValidationIndication.TotalPassed => "Total passed",
            SignatureValidationIndication.TotalFailed => "Total failed",
            SignatureValidationIndication.Indeterminate => "Indeterminate",
            _ => indication.ToString(),
        };

    /// <summary>Describes validation status.</summary>
    public string DescribeValidationStatus(ValidationStatus status) =>
        status switch
        {
            ValidationStatus.Passed => "Passed",
            ValidationStatus.Failed => "Failed",
            ValidationStatus.Unchecked => "Unchecked",
            ValidationStatus.Indeterminate => "Indeterminate",
            _ => status.ToString(),
        };

    /// <summary>Returns the validation type caption.</summary>
    public string ValidationTypeCaption(ValidationType type) =>
        type switch
        {
            ValidationType.Root => "Root",
            ValidationType.Structure => "Structure",
            ValidationType.StructureEdocDataObjectCount => "Data object count",
            ValidationType.StructurePdfPageCount => "PDF page count",
            ValidationType.StructureSignatureCount => "Signature count",
            ValidationType.Signature => "Signature",
            ValidationType.SignatureEdocDataObjectReferences => "Data object references (digest)",
            ValidationType.SignatureEdocSigningCertificateReferences => "Signing certificate references (XAdES)",
            ValidationType.SignatureMethod => "Signature method",
            ValidationType.SignaturePdfAdobePkcs7DetachedSignedAttributes => "PDF Adobe PKCS#7 signed attributes",
            ValidationType.SignaturePdfEtsiCadesDetachedSignedAttributes => "PDF ETSI CAdES signed attributes",
            ValidationType.SignatureProductionPlace => "Signature production place",
            ValidationType.SignatureProfile => "Signature profile",
            ValidationType.SignatureSignerClaimedRoles => "Signer claimed roles",
            ValidationType.SignatureSigningCertificate => "Certificate",
            ValidationType.SignatureSigningCertificateSerial => "Certificate serial (hex)",
            ValidationType.SignatureSigningCertificateValidity => "Certificate validity (UTC)",
            ValidationType.SignatureSigningCertificateNotBefore => "Not before (UTC)",
            ValidationType.SignatureSigningCertificateNotAfter => "Not after (UTC)",
            ValidationType.SignatureSigningCertificateChain => "Signing certificate chain",
            ValidationType.SignatureSigningCertificatePkixStatuses => "PKIX chain element status",
            ValidationType.SignatureSigningCertificateStatus => "Certificate / revocation status",
            ValidationType.SignatureRevocation => "Revocation",
            ValidationType.SignatureRevocationPkixChainMode => "PKIX revocation (chain build)",
            ValidationType.SignatureRevocationEmbeddedUnsigned => "Embedded RevocationValues",
            ValidationType.SignatureRevocationApplicationOnline => "Online revocation (application-controlled)",
            ValidationType.SignatureRevocationEmbeddedUnsignedArtifact => "Embedded revocation artifact",
            ValidationType.SignatureRevocationApplicationOnlineArtifact => "Online revocation artifact",
            ValidationType.SignatureTimestamp => "Signature timestamp",
            ValidationType.SignatureTimestampCertificate => "Timestamp certificate (TSA chain)",
            ValidationType.SignatureTimestampCertificateChain => "TSA certificate chain",
            ValidationType.SignatureTimestampSignature => "Timestamp token (CMS)",
            ValidationType.SignatureArchiveTimeStamp => "Archive time-stamps (XAdES-A)",
            ValidationType.SignatureArchiveTimeStampSignature => "Archive time-stamp token (CMS)",
            ValidationType.SignatureArchiveTimeStampCertificate => "Archive TSA certificate (PKIX)",
            ValidationType.SignatureArchiveTimeStampImprint => "Archive time-stamp imprint (digest input)",
            ValidationType.SignatureType => "Signature type",
            ValidationType.SignatureValue => "Signature value",
            _ => type.ToString(),
        };

    /// <summary>Describes signature profile.</summary>
    public string DescribeSignatureProfile(SignatureProfile profile) =>
        profile switch
        {
            SignatureProfile.BasicSignature => "BASIC (B-BES style)",
            SignatureProfile.QualifiedSignature => "QUALIFIED (LT-style material)",
            SignatureProfile.ArchivedSignature => "ARCHIVED (LTA)",
            SignatureProfile.ProprietarySignature => "Proprietary",
            SignatureProfile.UnknownSignature => "Unknown",
            _ => profile.ToString(),
        };

    /// <summary>Describes signature qualification.</summary>
    public string DescribeSignatureQualification(SignatureQualification q) =>
        q switch
        {
            SignatureQualification.QESig => "Qualified electronic signature",
            SignatureQualification.QESeal => "Qualified electronic seal",
            SignatureQualification.ADESig => "Advanced electronic signature",
            SignatureQualification.ADESeal => "Advanced electronic seal",
            SignatureQualification.Unknown => "Unknown",
            _ => q.ToString(),
        };

    /// <summary>Describes certificate qualification.</summary>
    public string DescribeCertificateQualification(CertificateQualification q) =>
        q.ToString();

    /// <summary>Describes timestamp qualification.</summary>
    public string DescribeTimestampQualification(TimestampQualification q) =>
        q switch
        {
            TimestampQualification.QTsa => "Qualified TSA",
            TimestampQualification.Tsa => "TSA",
            TimestampQualification.Unknown => "Unknown",
            _ => q.ToString(),
        };

    /// <summary>Describes validation signature type.</summary>
    public string DescribeValidationSignatureType(ValidationSignatureType type) =>
        type switch
        {
            ValidationSignatureType.EdocV1 => "EDOC v1",
            ValidationSignatureType.EdocV2 => "EDOC v2 (ASiC-E / XML)",
            ValidationSignatureType.PdfAdobePkcs7Detached => "PDF Adobe PKCS#7",
            ValidationSignatureType.PdfEtsiCadesDetached => "PDF ETSI CAdES",
            ValidationSignatureType.UnknownType => "Unknown",
            _ => type.ToString(),
        };

    /// <summary>Returns the legal-basis hint text.</summary>
    public string? LegalBasisHint(SignatureValidationIndication indication) =>
        indication switch
        {
            SignatureValidationIndication.TotalPassed =>
                "Cryptographic verification succeeded under the configured trust policy; legal qualification is host-defined.",
            SignatureValidationIndication.TotalFailed =>
                "Core XML-DSig verification failed; the signature cannot be trusted at the cryptographic level.",
            SignatureValidationIndication.Indeterminate =>
                "Cryptographic core passed but trust policy checks failed or were inconclusive; review the validation tree.",
            _ => null,
        };
}
