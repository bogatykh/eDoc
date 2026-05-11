using System.Collections.Generic;
using System.Globalization;
using eDocLib.Validation;

namespace eDocLib.Validation.Reporting;

/// <summary>
/// Wraps another <see cref="IValidationReportLocalizer"/> and replaces individual strings when a key is present in the
/// overrides dictionary. Keys use <c>{EnumTypeName}.{EnumMemberName}</c>, for example
/// <c>SignatureValidationIndication.TotalPassed</c>,
/// <c>ValidationStatus.Passed</c>, <c>ValidationType.Signature</c>, <c>SignatureProfile.BasicSignature</c>,
/// <c>ValidationSignatureType.EdocV2</c>, <c>LegalBasisHint.TotalFailed</c>.
/// </summary>
internal sealed class DictionaryValidationReportLocalizer : IValidationReportLocalizer
{
    private readonly IValidationReportLocalizer _fallback;
    private readonly IReadOnlyDictionary<string, string> _overrides;

    /// <summary>Initializes a new dictionary validation report localizer instance.</summary>
    /// <param name="overrides">String overrides keyed as <c>{EnumTypeName}.{value}</c> (see class remarks).</param>
    /// <param name="fallback">Fallback localizer; defaults to <see cref="DefaultValidationReportLocalizer"/>.</param>
    public DictionaryValidationReportLocalizer(
        IReadOnlyDictionary<string, string> overrides,
        IValidationReportLocalizer? fallback = null)
    {
        ArgumentNullException.ThrowIfNull(overrides);
        _overrides = overrides;
        _fallback = fallback ?? new DefaultValidationReportLocalizer();
    }

    /// <summary>Override map passed at construction.</summary>
    public IReadOnlyDictionary<string, string> Overrides => _overrides;

    /// <inheritdoc />
    public CultureInfo? Culture => _fallback.Culture;

    /// <summary>Returns the validation indication text.</summary>
    public string Indication(SignatureValidationIndication indication) =>
        Lookup(nameof(SignatureValidationIndication), indication.ToString()) ?? _fallback.Indication(indication);

    /// <summary>Describes validation status.</summary>
    public string DescribeValidationStatus(ValidationStatus status) =>
        Lookup(nameof(ValidationStatus), status.ToString()) ?? _fallback.DescribeValidationStatus(status);

    /// <summary>Returns the validation type caption.</summary>
    public string ValidationTypeCaption(ValidationType type) =>
        Lookup(nameof(ValidationType), type.ToString()) ?? _fallback.ValidationTypeCaption(type);

    /// <summary>Describes signature profile.</summary>
    public string DescribeSignatureProfile(SignatureProfile profile) =>
        Lookup(nameof(SignatureProfile), profile.ToString()) ?? _fallback.DescribeSignatureProfile(profile);

    /// <summary>Describes signature qualification.</summary>
    public string DescribeSignatureQualification(SignatureQualification qualification) =>
        Lookup(nameof(SignatureQualification), qualification.ToString())
        ?? _fallback.DescribeSignatureQualification(qualification);

    /// <summary>Describes certificate qualification.</summary>
    public string DescribeCertificateQualification(CertificateQualification qualification) =>
        Lookup(nameof(CertificateQualification), qualification.ToString())
        ?? _fallback.DescribeCertificateQualification(qualification);

    /// <summary>Describes timestamp qualification.</summary>
    public string DescribeTimestampQualification(TimestampQualification qualification) =>
        Lookup(nameof(TimestampQualification), qualification.ToString())
        ?? _fallback.DescribeTimestampQualification(qualification);

    /// <summary>Describes validation signature type.</summary>
    public string DescribeValidationSignatureType(ValidationSignatureType type) =>
        Lookup(nameof(ValidationSignatureType), type.ToString())
        ?? _fallback.DescribeValidationSignatureType(type);

    /// <summary>Returns the legal-basis hint text.</summary>
    public string? LegalBasisHint(SignatureValidationIndication indication)
    {
        var key = $"{nameof(LegalBasisHint)}.{indication}";
        if (_overrides.TryGetValue(key, out var text))
        {
            return string.IsNullOrEmpty(text) ? null : text;
        }

        return _fallback.LegalBasisHint(indication);
    }

    /// <summary>Looks up localized report text.</summary>
    private string? Lookup(string category, string name) =>
        _overrides.TryGetValue($"{category}.{name}", out var s) ? s : null;
}
