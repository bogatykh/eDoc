using eDocLib.Validation;
using Xunit;

namespace eDocLib.Tests;

public class TrustedListQualificationResolverTests
{
    private static TrustedListQualification Q(
        IReadOnlyList<string> currentTypes,
        string? currentStatus,
        IReadOnlyList<TrustedListServiceHistorySnapshot>? history) =>
        new()
        {
            ServiceTypeIdentifiers = currentTypes,
            ServiceStatusUri = currentStatus,
            ServiceHistory = history,
        };

    [Fact]
    public void ResolveEffectiveQualification_middle_segment_uses_history_row()
    {
        var t0 = new DateTimeOffset(2018, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var t1 = new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var hist = new[]
        {
            new TrustedListServiceHistorySnapshot
            {
                ServiceTypeIdentifiers = new[] { TslQualificationMapper.ServiceTypeQCertESign },
                ServiceStatusUri = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn",
                StatusStartingTime = t0,
            },
            new TrustedListServiceHistorySnapshot
            {
                ServiceTypeIdentifiers = new[] { TslQualificationMapper.ServiceTypeQCertESign },
                ServiceStatusUri = TslQualificationMapper.ServiceStatusGranted,
                StatusStartingTime = t1,
            },
        };

        var q = Q(
            new[] { TslQualificationMapper.ServiceTypeQCertESign },
            TslQualificationMapper.ServiceStatusGranted,
            hist);

        var mid = TrustedListQualificationResolver.ResolveEffectiveQualification(q, new DateTimeOffset(2019, 6, 1, 0, 0, 0, TimeSpan.Zero));
        Assert.Equal("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn", mid.ServiceStatusUri);

        var after = TrustedListQualificationResolver.ResolveEffectiveQualification(q, new DateTimeOffset(2021, 1, 1, 0, 0, 0, TimeSpan.Zero));
        Assert.Equal(TslQualificationMapper.ServiceStatusGranted, after.ServiceStatusUri);
    }

    [Fact]
    public void ResolveEffectiveQualification_no_history_returns_same_instance_semantics()
    {
        var q = Q(
            new[] { TslQualificationMapper.ServiceTypeQCertESign },
            TslQualificationMapper.ServiceStatusGranted,
            null);
        var r = TrustedListQualificationResolver.ResolveEffectiveQualification(q, DateTimeOffset.UtcNow);
        Assert.Same(q, r);
    }
}
