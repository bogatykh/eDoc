using eDocLib.Validation;
using Xunit;

namespace eDocLib.Tests;

public class TslQualificationIndicatorsTests
{
    [Fact]
    public void Record_equality_is_value_based()
    {
        var a = new TslQualificationIndicators(true, false, true, true);
        var b = new TslQualificationIndicators(true, false, true, true);

        Assert.Equal(a, b);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
    }

    [Fact]
    public void Record_inequality_when_any_field_differs()
    {
        var baseline = new TslQualificationIndicators(true, false, true, true);

        Assert.NotEqual(baseline, baseline with { SuggestsQualifiedElectronicSignature = false });
        Assert.NotEqual(baseline, baseline with { SuggestsQualifiedElectronicSeal = true });
        Assert.NotEqual(baseline, baseline with { SuggestsQualifiedTimestampService = false });
        Assert.NotEqual(baseline, baseline with { ServiceStatusIsGranted = false });
        Assert.NotEqual(baseline, baseline with { ServiceStatusIsGranted = null });
    }

    [Fact]
    public void With_clones_preserve_unchanged_fields()
    {
        var baseline = new TslQualificationIndicators(true, false, true, true);
        var copy = baseline with { ServiceStatusIsGranted = false };

        Assert.Equal(baseline.SuggestsQualifiedElectronicSignature, copy.SuggestsQualifiedElectronicSignature);
        Assert.Equal(baseline.SuggestsQualifiedElectronicSeal, copy.SuggestsQualifiedElectronicSeal);
        Assert.Equal(baseline.SuggestsQualifiedTimestampService, copy.SuggestsQualifiedTimestampService);
        Assert.False(copy.ServiceStatusIsGranted);
    }

    [Fact]
    public void Null_status_is_distinct_from_false_status()
    {
        var unknown = new TslQualificationIndicators(false, false, false, ServiceStatusIsGranted: null);
        var notGranted = new TslQualificationIndicators(false, false, false, ServiceStatusIsGranted: false);

        Assert.NotEqual(unknown, notGranted);
        Assert.Null(unknown.ServiceStatusIsGranted);
        Assert.False(notGranted.ServiceStatusIsGranted);
    }
}
