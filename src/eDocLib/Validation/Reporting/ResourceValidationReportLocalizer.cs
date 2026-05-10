using System.Globalization;
using System.Resources;

namespace eDocLib.Validation.Reporting;

/// <summary>
/// <see cref="IValidationReportLocalizer"/> backed by embedded <c>ValidationReportStrings</c> resources.
/// Keys use <c>{EnumTypeName}_{EnumMemberName}</c> (underscore), matching the default entries in the RESX file.
/// </summary>
internal sealed class ResourceValidationReportLocalizer : IValidationReportLocalizer
{
    /// <summary>Stores the resources.</summary>
    private readonly ResourceManager _resources;
    /// <summary>Stores the fallback.</summary>
    private readonly IValidationReportLocalizer _fallback;
    /// <summary>Stores the culture.</summary>
    private readonly CultureInfo? _culture;

    /// <summary>Initializes a new resource validation report localizer instance.</summary>
    /// <param name="resourceManager">Resource manager that resolves validation report strings.</param>
    /// <param name="culture">Optional culture used to look up resource values.</param>
    /// <param name="fallback">Optional fallback localizer used when a resource key is missing.</param>
    public ResourceValidationReportLocalizer(
        ResourceManager resourceManager,
        CultureInfo? culture = null,
        IValidationReportLocalizer? fallback = null)
    {
        ArgumentNullException.ThrowIfNull(resourceManager);
        _resources = resourceManager;
        _culture = culture;
        _fallback = fallback ?? new DefaultValidationReportLocalizer(culture);
    }

    /// <summary>Uses embedded <c>ValidationReportStrings.resx</c> from this assembly.</summary>
    public static ResourceValidationReportLocalizer ForEmbeddedDefaults(CultureInfo? culture = null) =>
        new(
            new ResourceManager(
                "eDocLib.Validation.Reporting.ValidationReportStrings",
                typeof(ResourceValidationReportLocalizer).Assembly),
            culture);

    /// <summary>Stores the culture.</summary>
    public CultureInfo? Culture => _culture ?? _fallback.Culture;

    /// <summary>Returns the validation indication text.</summary>
    public string Indication(SignatureValidationIndication indication) =>
        Get($"{nameof(SignatureValidationIndication)}_{indication}") ?? _fallback.Indication(indication);

    /// <summary>Describes validation status.</summary>
    public string DescribeValidationStatus(ValidationStatus status) =>
        Get($"{nameof(ValidationStatus)}_{status}") ?? _fallback.DescribeValidationStatus(status);

    /// <summary>Returns the validation type caption.</summary>
    public string ValidationTypeCaption(ValidationType type) =>
        Get($"{nameof(ValidationType)}_{type}") ?? _fallback.ValidationTypeCaption(type);

    /// <summary>Describes signature profile.</summary>
    public string DescribeSignatureProfile(SignatureProfile profile) =>
        Get($"{nameof(SignatureProfile)}_{profile}") ?? _fallback.DescribeSignatureProfile(profile);

    /// <summary>Describes signature qualification.</summary>
    public string DescribeSignatureQualification(SignatureQualification qualification) =>
        Get($"{nameof(SignatureQualification)}_{qualification}") ?? _fallback.DescribeSignatureQualification(qualification);

    /// <summary>Describes certificate qualification.</summary>
    public string DescribeCertificateQualification(CertificateQualification qualification) =>
        Get($"{nameof(CertificateQualification)}_{qualification}") ?? _fallback.DescribeCertificateQualification(qualification);

    /// <summary>Describes timestamp qualification.</summary>
    public string DescribeTimestampQualification(TimestampQualification qualification) =>
        Get($"{nameof(TimestampQualification)}_{qualification}") ?? _fallback.DescribeTimestampQualification(qualification);

    /// <summary>Describes validation signature type.</summary>
    public string DescribeValidationSignatureType(ValidationSignatureType type) =>
        Get($"{nameof(ValidationSignatureType)}_{type}") ?? _fallback.DescribeValidationSignatureType(type);

    /// <summary>Returns the legal-basis hint text.</summary>
    public string? LegalBasisHint(SignatureValidationIndication indication)
    {
        var key = $"{nameof(LegalBasisHint)}_{indication}";
        if (_resources.GetString(key, EffectiveCulture()) is { } s)
        {
            return string.IsNullOrEmpty(s) ? null : s;
        }

        return _fallback.LegalBasisHint(indication);
    }

    /// <summary>Gets value.</summary>
    private string? Get(string key) => _resources.GetString(key, EffectiveCulture());

    /// <summary>Returns the effective localization culture.</summary>
    private CultureInfo EffectiveCulture() => _culture ?? CultureInfo.CurrentUICulture;
}
