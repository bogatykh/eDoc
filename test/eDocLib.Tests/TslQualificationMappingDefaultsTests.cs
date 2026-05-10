using eDocLib.Validation;
using Xunit;

namespace eDocLib.Tests;

public class TslQualificationMappingDefaultsTests
{
    [Fact]
    public void Merge_unions_uri_collections_case_insensitively()
    {
        var a = new TslQualificationMappingOptions { ExtraGrantedLikeServiceStatusUris = new[] { "http://example/status-one" } };
        var b = new TslQualificationMappingOptions { ExtraGrantedLikeServiceStatusUris = new[] { "http://example/status-one", "http://example/status-two" } };
        var m = TslQualificationMappingOptions.Merge(a, b);
        Assert.NotNull(m);
        Assert.Equal(2, m!.ExtraGrantedLikeServiceStatusUris!.Count);
    }

    [Fact]
    public void LatvianNationalPublished_includes_etsi_accredited()
    {
        Assert.Contains(
            TslQualificationMapper.ServiceStatusAccredited,
            TslQualificationMappingDefaults.LatvianNationalPublished.ExtraGrantedLikeServiceStatusUris!,
            StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void Accredited_maps_to_granted_like_when_defaults_merged()
    {
        var opt = TslQualificationMappingOptions.Merge(
            TslQualificationMappingDefaults.LatvianNationalPublished,
            null);
        var m = TslQualificationMapper.Map(
            new[] { TslQualificationMapper.ServiceTypeQCertESign },
            TslQualificationMapper.ServiceStatusAccredited,
            opt);
        Assert.True(m.ServiceStatusIsGranted);
    }

    [Fact]
    public void Merge_preserves_host_extra_types_and_defaults()
    {
        const string extraType = "http://national.example/qes";
        var host = new TslQualificationMappingOptions { ExtraQualifiedEsignServiceTypeUris = new[] { extraType } };
        var merged = TslQualificationMappingOptions.Merge(TslQualificationMappingDefaults.LatvianNationalPublished, host);
        Assert.NotNull(merged);
        var map = TslQualificationMapper.Map(new[] { extraType }, TslQualificationMapper.ServiceStatusAccredited, merged);
        Assert.True(map.SuggestsQualifiedElectronicSignature);
        Assert.True(map.ServiceStatusIsGranted);
    }
}
