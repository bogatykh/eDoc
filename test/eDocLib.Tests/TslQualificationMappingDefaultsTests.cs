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

    [Fact]
    public void LatvianNationalPublished_recognises_legacy_qtst_service_type_uris()
    {
        Assert.Contains(
            TslQualificationMapper.ServiceTypeTsaTssQC,
            TslQualificationMappingDefaults.LatvianNationalPublished.ExtraQualifiedTimestampServiceTypeUris!,
            StringComparer.OrdinalIgnoreCase);
        Assert.Contains(
            TslQualificationMapper.ServiceTypeTsaTssAdESQCandQES,
            TslQualificationMappingDefaults.LatvianNationalPublished.ExtraQualifiedTimestampServiceTypeUris!,
            StringComparer.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(TslQualificationMapper.ServiceTypeTsaQTST)]
    [InlineData(TslQualificationMapper.ServiceTypeTsaTssQC)]
    [InlineData(TslQualificationMapper.ServiceTypeTsaTssAdESQCandQES)]
    public void Qualified_timestamp_service_uris_are_detected_when_defaults_merged(string serviceTypeUri)
    {
        var opt = TslQualificationMappingOptions.Merge(
            TslQualificationMappingDefaults.LatvianNationalPublished,
            null);
        var m = TslQualificationMapper.Map(
            new[] { serviceTypeUri },
            TslQualificationMapper.ServiceStatusGranted,
            opt);
        Assert.True(m.SuggestsQualifiedTimestampService);
        Assert.True(m.ServiceStatusIsGranted);
    }

    [Fact]
    public void Generic_tsa_service_uri_is_not_qualified_even_with_defaults()
    {
        var opt = TslQualificationMappingOptions.Merge(
            TslQualificationMappingDefaults.LatvianNationalPublished,
            null);
        var m = TslQualificationMapper.Map(
            new[] { TslQualificationMapper.ServiceTypeTsa },
            TslQualificationMapper.ServiceStatusGranted,
            opt);
        Assert.False(m.SuggestsQualifiedTimestampService);
        Assert.True(m.ServiceStatusIsGranted);
    }

    [Fact]
    public void Merge_returns_null_when_both_inputs_null()
    {
        Assert.Null(TslQualificationMappingOptions.Merge(null, null));
    }

    [Fact]
    public void Merge_clones_baseline_when_extras_null()
    {
        var baseline = new TslQualificationMappingOptions
        {
            ExtraGrantedLikeServiceStatusUris = new[] { "http://example/x" },
            ExtraQualifiedEsignServiceTypeUris = new[] { "http://example/sign" },
            ExtraQualifiedEsealServiceTypeUris = new[] { "http://example/seal" },
            ExtraQualifiedTimestampServiceTypeUris = new[] { "http://example/tsa" },
        };
        var merged = TslQualificationMappingOptions.Merge(baseline, null);
        Assert.NotNull(merged);
        Assert.NotSame(baseline, merged);
        Assert.Equal("http://example/x", Assert.Single(merged!.ExtraGrantedLikeServiceStatusUris!));
        Assert.Equal("http://example/sign", Assert.Single(merged.ExtraQualifiedEsignServiceTypeUris!));
        Assert.Equal("http://example/seal", Assert.Single(merged.ExtraQualifiedEsealServiceTypeUris!));
        Assert.Equal("http://example/tsa", Assert.Single(merged.ExtraQualifiedTimestampServiceTypeUris!));
    }

    [Fact]
    public void Merge_dedupes_case_insensitively_across_all_uri_collections()
    {
        var a = new TslQualificationMappingOptions
        {
            ExtraGrantedLikeServiceStatusUris = new[] { "http://example/STATUS" },
            ExtraQualifiedTimestampServiceTypeUris = new[] { "http://example/Q" },
        };
        var b = new TslQualificationMappingOptions
        {
            ExtraGrantedLikeServiceStatusUris = new[] { "http://example/status" },
            ExtraQualifiedTimestampServiceTypeUris = new[] { "http://example/q" },
        };

        var merged = TslQualificationMappingOptions.Merge(a, b);
        Assert.NotNull(merged);
        Assert.Single(merged!.ExtraGrantedLikeServiceStatusUris!);
        Assert.Single(merged.ExtraQualifiedTimestampServiceTypeUris!);
    }

    [Fact]
    public void Merge_trims_and_drops_whitespace_uris()
    {
        var a = new TslQualificationMappingOptions
        {
            ExtraQualifiedTimestampServiceTypeUris = new[] { "  http://example/q  ", "  ", "", "\t" },
        };
        var merged = TslQualificationMappingOptions.Merge(a, null);
        Assert.NotNull(merged);
        var uri = Assert.Single(merged!.ExtraQualifiedTimestampServiceTypeUris!);
        Assert.Equal("http://example/q", uri);
    }

    [Fact]
    public void Merge_returns_object_with_null_uri_collections_when_all_inputs_empty()
    {
        var a = new TslQualificationMappingOptions
        {
            ExtraQualifiedTimestampServiceTypeUris = new string[0],
        };
        var merged = TslQualificationMappingOptions.Merge(a, null);
        Assert.NotNull(merged);
        Assert.Null(merged!.ExtraQualifiedTimestampServiceTypeUris);
        Assert.Null(merged.ExtraGrantedLikeServiceStatusUris);
    }
}
