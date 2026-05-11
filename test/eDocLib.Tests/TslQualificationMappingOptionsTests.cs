using System;
using System.Linq;
using eDocLib.Validation;
using Xunit;

namespace eDocLib.Tests;

/// <summary>
/// Coverage for <see cref="TslQualificationMappingOptions"/>, especially the <see cref="TslQualificationMappingOptions.Merge"/>
/// union semantics: case-insensitivity, deduplication, whitespace handling, and the "null when nothing to merge" contract
/// that lets <c>SignatureTrustPolicy.ResolveQualificationMappingOptions</c> skip the mapper entirely.
/// </summary>
public class TslQualificationMappingOptionsTests
{
    [Fact]
    public void Merge_returns_null_when_both_inputs_are_null()
    {
        // Allows the validator to avoid constructing a no-op options object on every TSL evaluation.
        Assert.Null(TslQualificationMappingOptions.Merge(null, null));
    }

    [Fact]
    public void Merge_returns_options_with_only_baseline_when_extras_null()
    {
        var baseline = new TslQualificationMappingOptions
        {
            ExtraQualifiedTimestampServiceTypeUris = new[] { "http://example/qtsa" },
        };
        var merged = TslQualificationMappingOptions.Merge(baseline, null);
        Assert.NotNull(merged);
        Assert.Equal(new[] { "http://example/qtsa" }, merged!.ExtraQualifiedTimestampServiceTypeUris!.OrderBy(s => s));
        Assert.Null(merged.ExtraGrantedLikeServiceStatusUris);
        Assert.Null(merged.ExtraQualifiedEsignServiceTypeUris);
        Assert.Null(merged.ExtraQualifiedEsealServiceTypeUris);
    }

    [Fact]
    public void Merge_returns_options_with_only_extras_when_baseline_null()
    {
        var extras = new TslQualificationMappingOptions
        {
            ExtraGrantedLikeServiceStatusUris = new[] { "http://example/granted" },
        };
        var merged = TslQualificationMappingOptions.Merge(null, extras);
        Assert.NotNull(merged);
        Assert.Equal(new[] { "http://example/granted" }, merged!.ExtraGrantedLikeServiceStatusUris!.OrderBy(s => s));
    }

    [Fact]
    public void Merge_unions_all_four_uri_buckets()
    {
        var baseline = new TslQualificationMappingOptions
        {
            ExtraGrantedLikeServiceStatusUris = new[] { "status-a" },
            ExtraQualifiedEsignServiceTypeUris = new[] { "esign-a" },
            ExtraQualifiedEsealServiceTypeUris = new[] { "eseal-a" },
            ExtraQualifiedTimestampServiceTypeUris = new[] { "ts-a" },
        };
        var extras = new TslQualificationMappingOptions
        {
            ExtraGrantedLikeServiceStatusUris = new[] { "status-b" },
            ExtraQualifiedEsignServiceTypeUris = new[] { "esign-b" },
            ExtraQualifiedEsealServiceTypeUris = new[] { "eseal-b" },
            ExtraQualifiedTimestampServiceTypeUris = new[] { "ts-b" },
        };

        var merged = TslQualificationMappingOptions.Merge(baseline, extras);
        Assert.NotNull(merged);
        Assert.Equal(new[] { "status-a", "status-b" }, merged!.ExtraGrantedLikeServiceStatusUris!.OrderBy(s => s));
        Assert.Equal(new[] { "esign-a", "esign-b" }, merged.ExtraQualifiedEsignServiceTypeUris!.OrderBy(s => s));
        Assert.Equal(new[] { "eseal-a", "eseal-b" }, merged.ExtraQualifiedEsealServiceTypeUris!.OrderBy(s => s));
        Assert.Equal(new[] { "ts-a", "ts-b" }, merged.ExtraQualifiedTimestampServiceTypeUris!.OrderBy(s => s));
    }

    [Fact]
    public void Merge_deduplicates_case_insensitively_and_trims_whitespace()
    {
        var baseline = new TslQualificationMappingOptions
        {
            ExtraQualifiedTimestampServiceTypeUris = new[] { "HTTP://Example/QTSA", " http://example/qtsa " },
        };
        var extras = new TslQualificationMappingOptions
        {
            ExtraQualifiedTimestampServiceTypeUris = new[] { "http://example/qtsa", "http://example/OTHER" },
        };

        var merged = TslQualificationMappingOptions.Merge(baseline, extras);
        Assert.NotNull(merged);
        // Trimmed and deduplicated case-insensitively; exact preserved casing of first occurrence is implementation-defined.
        var actual = merged!.ExtraQualifiedTimestampServiceTypeUris!
            .Select(s => s.ToLowerInvariant())
            .OrderBy(s => s)
            .ToArray();
        Assert.Equal(new[] { "http://example/other", "http://example/qtsa" }, actual);
    }

    [Fact]
    public void Merge_drops_null_whitespace_and_empty_entries()
    {
        var baseline = new TslQualificationMappingOptions
        {
            ExtraGrantedLikeServiceStatusUris = new[] { string.Empty, "   ", "valid" },
        };
        var merged = TslQualificationMappingOptions.Merge(baseline, null);
        Assert.NotNull(merged);
        Assert.Equal(new[] { "valid" }, merged!.ExtraGrantedLikeServiceStatusUris!.OrderBy(s => s));
    }

    [Fact]
    public void Merge_yields_null_buckets_when_inputs_have_no_meaningful_entries()
    {
        // The "no-op" carrier: passing in empty/whitespace lists must still produce null buckets so the
        // downstream mapper short-circuits its merge logic instead of allocating an empty HashSet.
        var baseline = new TslQualificationMappingOptions
        {
            ExtraGrantedLikeServiceStatusUris = new[] { "   ", string.Empty },
        };
        var extras = new TslQualificationMappingOptions
        {
            ExtraQualifiedEsignServiceTypeUris = Array.Empty<string>(),
        };

        var merged = TslQualificationMappingOptions.Merge(baseline, extras);
        Assert.NotNull(merged);
        Assert.Null(merged!.ExtraGrantedLikeServiceStatusUris);
        Assert.Null(merged.ExtraQualifiedEsignServiceTypeUris);
        Assert.Null(merged.ExtraQualifiedEsealServiceTypeUris);
        Assert.Null(merged.ExtraQualifiedTimestampServiceTypeUris);
    }

    [Fact]
    public void Init_only_properties_default_to_null()
    {
        var o = new TslQualificationMappingOptions();
        Assert.Null(o.ExtraGrantedLikeServiceStatusUris);
        Assert.Null(o.ExtraQualifiedEsignServiceTypeUris);
        Assert.Null(o.ExtraQualifiedEsealServiceTypeUris);
        Assert.Null(o.ExtraQualifiedTimestampServiceTypeUris);
    }
}
