using System.Collections.Generic;
using eDocLib.Validation;
using Xunit;

namespace eDocLib.Tests;

public class TslQualificationMapperTests
{
    [Fact]
    public void Map_returns_all_false_when_inputs_null()
    {
        var ind = TslQualificationMapper.Map(serviceTypeIdentifiers: null, serviceStatusUri: null);

        Assert.False(ind.SuggestsQualifiedElectronicSignature);
        Assert.False(ind.SuggestsQualifiedElectronicSeal);
        Assert.False(ind.SuggestsQualifiedTimestampService);
        Assert.Null(ind.ServiceStatusIsGranted);
    }

    [Fact]
    public void Map_returns_all_false_for_empty_collection_and_whitespace_status()
    {
        var ind = TslQualificationMapper.Map(Array.Empty<string>(), "   \t  ");

        Assert.False(ind.SuggestsQualifiedElectronicSignature);
        Assert.False(ind.SuggestsQualifiedElectronicSeal);
        Assert.False(ind.SuggestsQualifiedTimestampService);
        Assert.Null(ind.ServiceStatusIsGranted);
    }

    [Theory]
    [InlineData(TslQualificationMapper.ServiceTypeQCertESign, true, false, false)]
    [InlineData(TslQualificationMapper.ServiceTypeQCertESeal, false, true, false)]
    [InlineData(TslQualificationMapper.ServiceTypeTsaQTST, false, false, true)]
    [InlineData(TslQualificationMapper.ServiceTypeTsa, false, false, false)]
    [InlineData(TslQualificationMapper.ServiceTypeTsaTssQC, false, false, false)]
    [InlineData(TslQualificationMapper.ServiceTypeTsaTssAdESQCandQES, false, false, false)]
    public void Map_recognises_each_built_in_service_type(
        string uri,
        bool expectedSign,
        bool expectedSeal,
        bool expectedQTsa)
    {
        var ind = TslQualificationMapper.Map(new[] { uri }, serviceStatusUri: null);

        Assert.Equal(expectedSign, ind.SuggestsQualifiedElectronicSignature);
        Assert.Equal(expectedSeal, ind.SuggestsQualifiedElectronicSeal);
        Assert.Equal(expectedQTsa, ind.SuggestsQualifiedTimestampService);
    }

    [Fact]
    public void Map_recognises_qsign_qseal_and_qtsa_when_all_three_listed()
    {
        var ind = TslQualificationMapper.Map(
            new[]
            {
                TslQualificationMapper.ServiceTypeQCertESign,
                TslQualificationMapper.ServiceTypeQCertESeal,
                TslQualificationMapper.ServiceTypeTsaQTST,
            },
            TslQualificationMapper.ServiceStatusGranted);

        Assert.True(ind.SuggestsQualifiedElectronicSignature);
        Assert.True(ind.SuggestsQualifiedElectronicSeal);
        Assert.True(ind.SuggestsQualifiedTimestampService);
        Assert.True(ind.ServiceStatusIsGranted);
    }

    [Fact]
    public void Map_trims_whitespace_around_service_type_uri()
    {
        var ind = TslQualificationMapper.Map(
            new[] { "  " + TslQualificationMapper.ServiceTypeTsaQTST + "  " },
            TslQualificationMapper.ServiceStatusGranted);

        Assert.True(ind.SuggestsQualifiedTimestampService);
        Assert.True(ind.ServiceStatusIsGranted);
    }

    [Fact]
    public void Map_ignores_null_and_whitespace_service_type_entries()
    {
        var ind = TslQualificationMapper.Map(
            new[] { null!, "", "   ", TslQualificationMapper.ServiceTypeTsaQTST },
            serviceStatusUri: null);

        Assert.True(ind.SuggestsQualifiedTimestampService);
    }

    [Theory]
    [InlineData(TslQualificationMapper.ServiceStatusGranted, true)]
    [InlineData(TslQualificationMapper.ServiceStatusRecognisedAtNationalLevel, true)]
    [InlineData(TslQualificationMapper.ServiceStatusAccredited, false)]
    [InlineData("http://example.invalid/unknown", false)]
    public void Map_status_granted_distinguishes_only_built_in_set(string status, bool expectedGranted)
    {
        var ind = TslQualificationMapper.Map(Array.Empty<string>(), status);
        Assert.Equal(expectedGranted, ind.ServiceStatusIsGranted);
    }

    [Fact]
    public void Map_status_uri_match_is_case_insensitive_after_trim()
    {
        var upper = TslQualificationMapper.ServiceStatusGranted.ToUpperInvariant();
        var ind = TslQualificationMapper.Map(Array.Empty<string>(), "  " + upper + "  ");

        Assert.True(ind.ServiceStatusIsGranted);
    }

    [Fact]
    public void Map_service_type_match_is_case_insensitive()
    {
        var upper = TslQualificationMapper.ServiceTypeTsaQTST.ToUpperInvariant();
        var ind = TslQualificationMapper.Map(new[] { upper }, TslQualificationMapper.ServiceStatusGranted);

        Assert.True(ind.SuggestsQualifiedTimestampService);
    }

    [Fact]
    public void Map_extra_options_extend_built_in_qtsa_uris()
    {
        const string nationalQtsa = "http://national.example/tsa/qualified";
        var opt = new TslQualificationMappingOptions
        {
            ExtraQualifiedTimestampServiceTypeUris = new[] { nationalQtsa },
        };

        var ind = TslQualificationMapper.Map(new[] { nationalQtsa }, TslQualificationMapper.ServiceStatusGranted, opt);
        Assert.True(ind.SuggestsQualifiedTimestampService);
        Assert.True(ind.ServiceStatusIsGranted);
    }

    [Fact]
    public void Map_extra_options_extend_granted_status_uris()
    {
        const string nationalStatus = "http://national.example/status/active";
        var opt = new TslQualificationMappingOptions
        {
            ExtraGrantedLikeServiceStatusUris = new[] { nationalStatus },
        };

        var ind = TslQualificationMapper.Map(
            new[] { TslQualificationMapper.ServiceTypeQCertESign },
            nationalStatus,
            opt);

        Assert.True(ind.ServiceStatusIsGranted);
        Assert.True(ind.SuggestsQualifiedElectronicSignature);
    }

    [Fact]
    public void Map_status_granted_returns_false_when_status_unknown()
    {
        var ind = TslQualificationMapper.Map(
            new[] { TslQualificationMapper.ServiceTypeTsaQTST },
            "http://example.invalid/somestatus");

        Assert.True(ind.SuggestsQualifiedTimestampService);
        Assert.False(ind.ServiceStatusIsGranted);
    }

    [Fact]
    public void Map_status_granted_returns_null_when_status_uri_omitted()
    {
        var ind = TslQualificationMapper.Map(
            new[] { TslQualificationMapper.ServiceTypeTsaQTST },
            serviceStatusUri: null);

        Assert.Null(ind.ServiceStatusIsGranted);
    }

    [Fact]
    public void Map_does_not_mutate_options_collections_across_calls()
    {
        var extra = new List<string> { "http://example.invalid/keep" };
        var opt = new TslQualificationMappingOptions { ExtraQualifiedTimestampServiceTypeUris = extra };

        _ = TslQualificationMapper.Map(new[] { TslQualificationMapper.ServiceTypeTsaQTST }, null, opt);
        _ = TslQualificationMapper.Map(new[] { TslQualificationMapper.ServiceTypeTsaQTST }, null, opt);

        Assert.Single(extra);
        Assert.Equal("http://example.invalid/keep", extra[0]);
    }
}
