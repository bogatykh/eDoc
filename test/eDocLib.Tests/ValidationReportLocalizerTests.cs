using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using eDocLib.Validation;
using eDocLib.Validation.Reporting;
using Xunit;

namespace eDocLib.Tests;

/// <summary>
/// Coverage for <see cref="DefaultValidationReportLocalizer"/>, <see cref="DictionaryValidationReportLocalizer"/>,
/// and <see cref="ResourceValidationReportLocalizer"/>. Audits that every enum value used in reporting has a
/// non-empty localized string in every localizer so reports never leak raw enum names to users.
/// </summary>
public class ValidationReportLocalizerTests
{
    [Fact]
    public void Default_localizer_returns_non_empty_string_for_every_indication_value()
    {
        var loc = new DefaultValidationReportLocalizer();
        foreach (SignatureValidationIndication v in Enum.GetValues<SignatureValidationIndication>())
        {
            var s = loc.Indication(v);
            Assert.False(string.IsNullOrWhiteSpace(s), $"Indication({v}) returned empty string.");
        }
    }

    [Fact]
    public void Default_localizer_returns_non_empty_string_for_every_status_value()
    {
        var loc = new DefaultValidationReportLocalizer();
        foreach (ValidationStatus v in Enum.GetValues<ValidationStatus>())
        {
            var s = loc.DescribeValidationStatus(v);
            Assert.False(string.IsNullOrWhiteSpace(s), $"DescribeValidationStatus({v}) returned empty string.");
        }
    }

    [Fact]
    public void Default_localizer_returns_non_empty_string_for_every_validation_type()
    {
        // This is the largest enum and the most likely to drift when a new node type is added.
        // A missing arm here would either silently fall through to ToString() (acceptable for "Root")
        // or break the report; this audit catches missing arms before they ship.
        var loc = new DefaultValidationReportLocalizer();
        foreach (ValidationType v in Enum.GetValues<ValidationType>())
        {
            var s = loc.ValidationTypeCaption(v);
            Assert.False(string.IsNullOrWhiteSpace(s), $"ValidationTypeCaption({v}) returned empty string.");
        }
    }

    [Fact]
    public void Default_localizer_returns_non_empty_string_for_every_signature_profile()
    {
        var loc = new DefaultValidationReportLocalizer();
        foreach (SignatureProfile v in Enum.GetValues<SignatureProfile>())
        {
            var s = loc.DescribeSignatureProfile(v);
            Assert.False(string.IsNullOrWhiteSpace(s), $"DescribeSignatureProfile({v}) returned empty string.");
        }
    }

    [Fact]
    public void Default_localizer_returns_non_empty_string_for_every_signature_qualification()
    {
        var loc = new DefaultValidationReportLocalizer();
        foreach (SignatureQualification v in Enum.GetValues<SignatureQualification>())
        {
            var s = loc.DescribeSignatureQualification(v);
            Assert.False(string.IsNullOrWhiteSpace(s), $"DescribeSignatureQualification({v}) returned empty string.");
        }
    }

    [Fact]
    public void Default_localizer_returns_non_empty_string_for_every_certificate_qualification()
    {
        var loc = new DefaultValidationReportLocalizer();
        foreach (CertificateQualification v in Enum.GetValues<CertificateQualification>())
        {
            var s = loc.DescribeCertificateQualification(v);
            Assert.False(string.IsNullOrWhiteSpace(s), $"DescribeCertificateQualification({v}) returned empty string.");
        }
    }

    [Fact]
    public void Default_localizer_returns_non_empty_string_for_every_timestamp_qualification()
    {
        var loc = new DefaultValidationReportLocalizer();
        foreach (TimestampQualification v in Enum.GetValues<TimestampQualification>())
        {
            var s = loc.DescribeTimestampQualification(v);
            Assert.False(string.IsNullOrWhiteSpace(s), $"DescribeTimestampQualification({v}) returned empty string.");
        }
    }

    [Fact]
    public void Default_localizer_returns_non_empty_string_for_every_signature_type()
    {
        var loc = new DefaultValidationReportLocalizer();
        foreach (ValidationSignatureType v in Enum.GetValues<ValidationSignatureType>())
        {
            var s = loc.DescribeValidationSignatureType(v);
            Assert.False(string.IsNullOrWhiteSpace(s), $"DescribeValidationSignatureType({v}) returned empty string.");
        }
    }

    [Fact]
    public void Default_localizer_returns_legal_hint_for_every_indication()
    {
        // LegalBasisHint can legitimately return null for unknown indications, but every defined value should produce a hint.
        var loc = new DefaultValidationReportLocalizer();
        foreach (SignatureValidationIndication v in Enum.GetValues<SignatureValidationIndication>())
        {
            var hint = loc.LegalBasisHint(v);
            Assert.False(string.IsNullOrWhiteSpace(hint), $"LegalBasisHint({v}) returned empty string.");
        }
    }

    [Fact]
    public void Default_localizer_qualifications_describe_qualified_terms()
    {
        var loc = new DefaultValidationReportLocalizer();
        Assert.Equal("Qualified electronic signature", loc.DescribeSignatureQualification(SignatureQualification.QESig));
        Assert.Equal("Qualified electronic seal", loc.DescribeSignatureQualification(SignatureQualification.QESeal));
        Assert.Equal("Qualified TSA", loc.DescribeTimestampQualification(TimestampQualification.QTsa));
    }

    [Fact]
    public void Default_localizer_validation_type_caption_for_qualification_leaf_mentions_TSL()
    {
        var loc = new DefaultValidationReportLocalizer();
        var caption = loc.ValidationTypeCaption(ValidationType.SignatureTimestampQualification);
        Assert.Contains("Timestamp qualification", caption, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("TSL", caption, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Dictionary_localizer_overrides_individual_keys_only()
    {
        var overrides = new Dictionary<string, string>
        {
            ["ValidationType.Signature"] = "Sig",
            ["TimestampQualification.QTsa"] = "QTSA-Override",
            ["LegalBasisHint.TotalPassed"] = "Custom hint.",
        };
        var loc = new DictionaryValidationReportLocalizer(overrides);

        Assert.Equal("Sig", loc.ValidationTypeCaption(ValidationType.Signature));
        Assert.Equal("QTSA-Override", loc.DescribeTimestampQualification(TimestampQualification.QTsa));
        Assert.Equal("Custom hint.", loc.LegalBasisHint(SignatureValidationIndication.TotalPassed));
        // Unspecified keys still fall back to defaults.
        Assert.Equal("Tsa".Length, loc.DescribeTimestampQualification(TimestampQualification.Tsa).Length);
    }

    [Fact]
    public void Dictionary_localizer_passes_through_to_fallback_when_no_override()
    {
        var overrides = new Dictionary<string, string>();
        var fallback = new DefaultValidationReportLocalizer();
        var loc = new DictionaryValidationReportLocalizer(overrides, fallback);

        Assert.Equal(fallback.ValidationTypeCaption(ValidationType.Signature),
            loc.ValidationTypeCaption(ValidationType.Signature));
        Assert.Equal(fallback.DescribeTimestampQualification(TimestampQualification.QTsa),
            loc.DescribeTimestampQualification(TimestampQualification.QTsa));
    }

    [Fact]
    public void Dictionary_localizer_legal_hint_empty_override_treated_as_null()
    {
        var overrides = new Dictionary<string, string>
        {
            ["LegalBasisHint.Indeterminate"] = string.Empty,
        };
        var loc = new DictionaryValidationReportLocalizer(overrides);

        Assert.Null(loc.LegalBasisHint(SignatureValidationIndication.Indeterminate));
    }

    [Fact]
    public void Dictionary_localizer_constructor_requires_non_null_overrides_dictionary()
    {
        Assert.Throws<ArgumentNullException>(() => new DictionaryValidationReportLocalizer(null!));
    }

    [Fact]
    public void Resource_localizer_returns_resx_values_for_every_enum_value()
    {
        // The embedded resx is the canonical translation surface. Every enum value used in reporting must
        // have a matching ResX key so host applications can ship a translated bundle confident the keys exist.
        var loc = ResourceValidationReportLocalizer.ForEmbeddedDefaults(CultureInfo.InvariantCulture);

        foreach (SignatureValidationIndication v in Enum.GetValues<SignatureValidationIndication>())
        {
            var s = loc.Indication(v);
            Assert.False(string.IsNullOrWhiteSpace(s));
        }

        foreach (ValidationStatus v in Enum.GetValues<ValidationStatus>())
        {
            var s = loc.DescribeValidationStatus(v);
            Assert.False(string.IsNullOrWhiteSpace(s));
        }

        foreach (ValidationType v in Enum.GetValues<ValidationType>())
        {
            var s = loc.ValidationTypeCaption(v);
            Assert.False(string.IsNullOrWhiteSpace(s), $"ValidationType {v} has no resx entry.");
        }

        foreach (SignatureProfile v in Enum.GetValues<SignatureProfile>())
        {
            var s = loc.DescribeSignatureProfile(v);
            Assert.False(string.IsNullOrWhiteSpace(s));
        }

        foreach (SignatureQualification v in Enum.GetValues<SignatureQualification>())
        {
            var s = loc.DescribeSignatureQualification(v);
            Assert.False(string.IsNullOrWhiteSpace(s));
        }

        foreach (CertificateQualification v in Enum.GetValues<CertificateQualification>())
        {
            var s = loc.DescribeCertificateQualification(v);
            Assert.False(string.IsNullOrWhiteSpace(s));
        }

        foreach (TimestampQualification v in Enum.GetValues<TimestampQualification>())
        {
            var s = loc.DescribeTimestampQualification(v);
            Assert.False(string.IsNullOrWhiteSpace(s));
        }

        foreach (ValidationSignatureType v in Enum.GetValues<ValidationSignatureType>())
        {
            var s = loc.DescribeValidationSignatureType(v);
            Assert.False(string.IsNullOrWhiteSpace(s));
        }

        foreach (SignatureValidationIndication v in Enum.GetValues<SignatureValidationIndication>())
        {
            var s = loc.LegalBasisHint(v);
            Assert.False(string.IsNullOrWhiteSpace(s), $"LegalBasisHint {v} has no resx entry.");
        }
    }

    [Fact]
    public void Resource_localizer_describes_qualified_timestamp_with_translated_string()
    {
        var loc = ResourceValidationReportLocalizer.ForEmbeddedDefaults(CultureInfo.InvariantCulture);
        Assert.Equal("Qualified TSA", loc.DescribeTimestampQualification(TimestampQualification.QTsa));
        Assert.Equal("Timestamp qualification (TSL)",
            loc.ValidationTypeCaption(ValidationType.SignatureTimestampQualification));
    }

    [Fact]
    public void Resource_localizer_falls_back_to_default_for_unknown_culture_keys()
    {
        // Use a culture for which there is no satellite assembly; ResourceManager will resolve from neutral.
        var loc = ResourceValidationReportLocalizer.ForEmbeddedDefaults(new CultureInfo("zz"));
        Assert.False(string.IsNullOrWhiteSpace(loc.DescribeTimestampQualification(TimestampQualification.QTsa)));
    }

    [Fact]
    public void Resource_localizer_constructor_requires_non_null_resource_manager()
    {
        Assert.Throws<ArgumentNullException>(() => new ResourceValidationReportLocalizer(null!));
    }

    [Fact]
    public void Localizers_agree_on_qualified_timestamp_description()
    {
        // Default localizer is the in-code source of truth; resx must agree (consistent host messaging).
        var def = new DefaultValidationReportLocalizer();
        var res = ResourceValidationReportLocalizer.ForEmbeddedDefaults(CultureInfo.InvariantCulture);
        Assert.Equal(
            def.DescribeTimestampQualification(TimestampQualification.QTsa),
            res.DescribeTimestampQualification(TimestampQualification.QTsa));
        Assert.Equal(
            def.ValidationTypeCaption(ValidationType.SignatureTimestampQualification),
            res.ValidationTypeCaption(ValidationType.SignatureTimestampQualification));
    }

    [Fact]
    public void Resource_localizer_emits_distinct_strings_for_distinct_enum_values()
    {
        // Guard against accidental sharing/copy-paste mistakes: every ValidationType caption is unique.
        var loc = ResourceValidationReportLocalizer.ForEmbeddedDefaults(CultureInfo.InvariantCulture);
        var values = Enum.GetValues<ValidationType>().Select(loc.ValidationTypeCaption).ToList();
        Assert.Equal(values.Count, values.Distinct(StringComparer.Ordinal).Count());
    }
}
