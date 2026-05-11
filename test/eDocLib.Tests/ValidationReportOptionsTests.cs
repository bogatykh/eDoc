using System;
using System.Globalization;
using eDocLib.Validation;
using eDocLib.Validation.Reporting;
using Xunit;

namespace eDocLib.Tests;

/// <summary>
/// Coverage for <see cref="ValidationReportOptions"/>: the public init-only record carrying the validator's
/// report-rendering knobs. Tests pin the contract that defaults are null (deferring to host-side defaults)
/// and that the record's value equality is honest about both fields so callers can compare snapshots.
/// </summary>
public class ValidationReportOptionsTests
{
    [Fact]
    public void Defaults_are_null_so_the_factory_can_apply_built_in_fallbacks()
    {
        var opts = new ValidationReportOptions();
        Assert.Null(opts.ReferenceTimeUtc);
        Assert.Null(opts.ReportLocalizer);
    }

    [Fact]
    public void Init_only_properties_capture_provided_values_verbatim()
    {
        var when = DateTimeOffset.Parse("2024-05-02T00:00:00Z");
        var localizer = new RecordingLocalizer();
        var opts = new ValidationReportOptions
        {
            ReferenceTimeUtc = when,
            ReportLocalizer = localizer,
        };
        Assert.Equal(when, opts.ReferenceTimeUtc);
        Assert.Same(localizer, opts.ReportLocalizer);
    }

    [Fact]
    public void Records_with_equal_field_set_are_equal()
    {
        var when = DateTimeOffset.Parse("2024-05-02T00:00:00Z");
        var localizer = new RecordingLocalizer();
        var a = new ValidationReportOptions { ReferenceTimeUtc = when, ReportLocalizer = localizer };
        var b = new ValidationReportOptions { ReferenceTimeUtc = when, ReportLocalizer = localizer };
        Assert.Equal(a, b);
    }

    [Fact]
    public void Records_with_different_reference_time_are_not_equal()
    {
        var a = new ValidationReportOptions { ReferenceTimeUtc = DateTimeOffset.UnixEpoch };
        var b = new ValidationReportOptions { ReferenceTimeUtc = DateTimeOffset.UnixEpoch.AddSeconds(1) };
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Records_with_different_localizer_reference_are_not_equal()
    {
        // ReportLocalizer is an interface — reference equality drives the record's GetHashCode/Equals.
        // Two distinct instances of the same class must therefore compare not-equal even when behaviour is identical.
        var a = new ValidationReportOptions { ReportLocalizer = new RecordingLocalizer() };
        var b = new ValidationReportOptions { ReportLocalizer = new RecordingLocalizer() };
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void With_expression_clones_and_changes_one_field()
    {
        var when = DateTimeOffset.Parse("2024-05-02T00:00:00Z");
        var localizer = new RecordingLocalizer();
        var a = new ValidationReportOptions { ReferenceTimeUtc = when, ReportLocalizer = localizer };
        var b = a with { ReferenceTimeUtc = null };

        Assert.Null(b.ReferenceTimeUtc);
        Assert.Same(localizer, b.ReportLocalizer);
        Assert.NotEqual(a, b);
    }

    private sealed class RecordingLocalizer : IValidationReportLocalizer
    {
        public CultureInfo? Culture => CultureInfo.InvariantCulture;
        public string Indication(SignatureValidationIndication indication) => indication.ToString();
        public string DescribeValidationStatus(ValidationStatus status) => status.ToString();
        public string ValidationTypeCaption(ValidationType type) => type.ToString();
        public string DescribeSignatureProfile(SignatureProfile profile) => profile.ToString();
        public string DescribeSignatureQualification(SignatureQualification qualification) => qualification.ToString();
        public string DescribeCertificateQualification(CertificateQualification qualification) => qualification.ToString();
        public string DescribeTimestampQualification(TimestampQualification qualification) => qualification.ToString();
        public string DescribeValidationSignatureType(ValidationSignatureType type) => type.ToString();
        public string? LegalBasisHint(SignatureValidationIndication indication) => null;
    }
}
