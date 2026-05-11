using Xunit;

namespace eDocLib.Tests;

/// <summary>
/// Coverage for the <see cref="SignatureProductionPlace"/> record: default null fields, equality, and
/// the canonical "all-null" sentinel that <see cref="eDocLib.Asic.Xades.XadesSignature"/> uses to mean
/// "no place asserted".
/// </summary>
public class SignatureProductionPlaceTests
{
    [Fact]
    public void Default_ctor_produces_all_null_fields()
    {
        // Sentinel for "no SignatureProductionPlace element"; parser returns null rather than this
        // all-null record, but constructing it directly is the round-trip endpoint for serializers that
        // round-trip back to/from the record.
        var p = new SignatureProductionPlace();
        Assert.Null(p.City);
        Assert.Null(p.StateOrProvince);
        Assert.Null(p.PostalCode);
        Assert.Null(p.CountryName);
    }

    [Fact]
    public void Positional_fields_are_stored_verbatim()
    {
        var p = new SignatureProductionPlace("Riga", "Latgale", "LV-1050", "LV");
        Assert.Equal("Riga", p.City);
        Assert.Equal("Latgale", p.StateOrProvince);
        Assert.Equal("LV-1050", p.PostalCode);
        Assert.Equal("LV", p.CountryName);
    }

    [Fact]
    public void Value_equality_holds_for_equal_field_set()
    {
        var a = new SignatureProductionPlace("Riga", null, null, "LV");
        var b = new SignatureProductionPlace("Riga", null, null, "LV");
        Assert.Equal(a, b);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
    }

    [Fact]
    public void Value_inequality_distinguishes_each_positional_field()
    {
        var baseline = new SignatureProductionPlace("Riga", "Latgale", "LV-1050", "LV");
        Assert.NotEqual(baseline, baseline with { City = "Vilnius" });
        Assert.NotEqual(baseline, baseline with { StateOrProvince = "Other" });
        Assert.NotEqual(baseline, baseline with { PostalCode = "00000" });
        Assert.NotEqual(baseline, baseline with { CountryName = "LT" });
    }

    [Fact]
    public void With_expression_clones_and_changes_one_field()
    {
        var baseline = new SignatureProductionPlace("Riga", "Latgale", "LV-1050", "LV");
        var clone = baseline with { City = "Daugavpils" };
        Assert.Equal("Daugavpils", clone.City);
        Assert.Equal(baseline.StateOrProvince, clone.StateOrProvince);
        Assert.Equal(baseline.PostalCode, clone.PostalCode);
        Assert.Equal(baseline.CountryName, clone.CountryName);
    }

    [Fact]
    public void Reference_equality_is_not_value_equality()
    {
        // sealed record: ReferenceEquals must not stand in for record equality and vice versa.
        var a = new SignatureProductionPlace("Riga", null, null, "LV");
        var b = new SignatureProductionPlace("Riga", null, null, "LV");
        Assert.False(ReferenceEquals(a, b));
        Assert.Equal(a, b);
    }
}
