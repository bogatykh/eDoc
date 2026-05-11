using System.Collections.Generic;
using eDocLib.Validation;
using Xunit;

namespace eDocLib.Tests;

/// <summary>
/// Coverage for <see cref="TimeStampTokenDerVerifyResult"/> and its TSL evaluation sibling: factory
/// invariants (so policy-flag bookkeeping stays consistent in the validator) and record-struct value
/// equality so callers can <c>==</c>-compare outcomes in assertions without surprises.
/// </summary>
public class TimeStampTokenDerVerifyResultTests
{
    [Fact]
    public void Success_factory_sets_ok_true_and_clears_error()
    {
        var r = TimeStampTokenDerVerifyResult.Success(cmsValid: true, chainValid: true, chain: null);
        Assert.True(r.Ok);
        Assert.Null(r.Error);
        Assert.True(r.CmsValid);
        Assert.True(r.ChainValid);
        Assert.Null(r.CertificateChain);
        Assert.Null(r.Tsl);
    }

    [Fact]
    public void Success_factory_propagates_optional_tsl_snapshot()
    {
        var tsl = new TimestampAuthorityTrustedListEvaluation(
            Listed: true,
            ServiceTypeIdentifiers: new[] { "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST" },
            ServiceStatusUri: "http://uri.etsi.org/TrstSvc/Svcstatus/granted",
            Indicators: new TslQualificationIndicators(true, false, true, true));

        var r = TimeStampTokenDerVerifyResult.Success(cmsValid: true, chainValid: null, chain: null, tsl: tsl);
        Assert.True(r.Ok);
        Assert.Equal(tsl, r.Tsl);
    }

    [Fact]
    public void Fail_factory_sets_ok_false_and_preserves_partial_diagnostics()
    {
        // Important contract: when CMS verification produced a definitive false, the Fail factory must keep
        // that signal so reporting can surface "CMS failed" instead of "unchecked".
        var chain = new[]
        {
            new CertificateChainDiagnostic(
                Index: 0,
                Subject: "CN=tsa",
                Issuer: "CN=tsa",
                Thumbprint: "00",
                SerialNumberHex: "01",
                NotBeforeUtc: System.DateTimeOffset.UnixEpoch,
                NotAfterUtc: System.DateTimeOffset.UnixEpoch.AddYears(1),
                ElementStatuses: System.Array.Empty<System.Security.Cryptography.X509Certificates.X509ChainStatus>()),
        };

        var r = TimeStampTokenDerVerifyResult.Fail("cms-mismatch", cmsValid: false, chainValid: null, chain: chain);
        Assert.False(r.Ok);
        Assert.Equal("cms-mismatch", r.Error);
        Assert.False(r.CmsValid);
        Assert.Null(r.ChainValid);
        Assert.Same(chain, r.CertificateChain);
    }

    [Fact]
    public void Fail_factory_keeps_tsl_snapshot_when_explicit_failure_occurs_after_tsl_lookup()
    {
        // Regression: validator computes the TSL snapshot before chain validation. If chain fails, the TSL
        // snapshot must still propagate to the report so consumers see "listed in TSL but chain broken".
        var tsl = new TimestampAuthorityTrustedListEvaluation(
            Listed: true, ServiceTypeIdentifiers: null, ServiceStatusUri: null, Indicators: null);
        var r = TimeStampTokenDerVerifyResult.Fail("chain-revoked", cmsValid: true, chainValid: false, chain: null, tsl: tsl);
        Assert.False(r.Ok);
        Assert.Equal(tsl, r.Tsl);
    }

    [Fact]
    public void Value_equality_holds_for_equal_field_set()
    {
        var a = TimeStampTokenDerVerifyResult.Success(true, true, null);
        var b = TimeStampTokenDerVerifyResult.Success(true, true, null);
        Assert.Equal(a, b);
        Assert.True(a == b);
    }

    [Fact]
    public void Value_inequality_distinguishes_each_field()
    {
        var ok = TimeStampTokenDerVerifyResult.Success(true, true, null);
        Assert.NotEqual(ok, ok with { Ok = false });
        Assert.NotEqual(ok, ok with { Error = "x" });
        Assert.NotEqual(ok, ok with { CmsValid = null });
        Assert.NotEqual(ok, ok with { ChainValid = false });
    }

    [Fact]
    public void Tsl_evaluation_record_supports_value_equality_and_with_expressions()
    {
        var a = new TimestampAuthorityTrustedListEvaluation(
            Listed: true,
            ServiceTypeIdentifiers: new[] { "uri-a" },
            ServiceStatusUri: "granted",
            Indicators: null);
        var b = a;
        Assert.Equal(a, b);

        var c = a with { Listed = false };
        Assert.NotEqual(a, c);
    }
}
