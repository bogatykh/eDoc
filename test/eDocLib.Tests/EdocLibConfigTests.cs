using System.IO;
using eDocLib;
using eDocLib.Configuration;
using eDocLib.Timestamp;
using Xunit;

namespace eDocLib.Tests;

public class EdocLibConfigTests
{
    [Fact]
    public void Default_snapshot_has_expected_starter_urls()
    {
        var doc = EdocLibConfig.Default;
        Assert.NotNull(doc.TslRelayUriPrefix);
        Assert.Contains("epout.eparaksts.lv", doc.TslRelayUriPrefix, StringComparison.OrdinalIgnoreCase);
        Assert.NotNull(doc.TimestampResponders);
        var route = Assert.Single(doc.TimestampResponders);
        Assert.Equal("issuerThumbprint", route.Kind, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("tsa.eparaksts.lv", route.HttpEndpoint, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("0eff893e7f5e6debb567a20ae7b3785cfb93bce9", route.ThumbprintSha1Hex, StringComparer.OrdinalIgnoreCase);
        Assert.NotNull(doc.OnlineRevocation);
        Assert.False(doc.OnlineRevocation!.FetchDeltaCrlViaFreshestCdp);
        Assert.False(EdocLibConfig.ResolveFetchDeltaCrlViaFreshestCdp(doc));
        Assert.Null(doc.PayloadMemoryThresholdBytes);
        Assert.Null(doc.PayloadSpillTempDirectory);
    }

    [Fact]
    public void ResolveFetchDeltaCrlViaFreshestCdp_true_when_online_revocation_sets_it()
    {
        var doc = EdocLibConfigBuilder.Create()
            .WithOnlineRevocation(new EdocLibOnlineRevocationSettings { FetchDeltaCrlViaFreshestCdp = true })
            .Build();
        Assert.True(EdocLibConfig.ResolveFetchDeltaCrlViaFreshestCdp(doc));
    }

    [Fact]
    public void TimestampResponderRegistry_RegisterFrom_unknown_kind_throws()
    {
        var doc = EdocLibConfigBuilder.Create()
            .WithTimestampResponders(
            [
                new EdocLibTimestampRoute
                {
                    Kind = "unknown",
                    ThumbprintSha1Hex = "ab",
                    HttpEndpoint = "https://example.invalid/rfc3161",
                },
            ])
            .Build();

        Assert.Throws<InvalidOperationException>(() =>
            new TimestampResponderRegistry().RegisterFrom(doc));
    }

    [Fact]
    public void Config_Open_accepts_payload_threshold()
    {
        var payload = new byte[128];
        Random.Shared.NextBytes(payload);
        using var built = Edoc.CreateNew();
        built.AddDataFile(new MemoryStream(payload), "p.bin", "application/octet-stream");
        using var zip = new MemoryStream();
        built.Save(zip);
        zip.Position = 0;

        var doc = EdocLibConfigBuilder.Create()
            .WithPayloadMemoryThresholdBytes(0)
            .Build();
        using var loaded = Edoc.Open(doc, zip);
        var df = Assert.Single(loaded.DataFiles);
        Assert.IsAssignableFrom<FileStream>(df.Stream);
    }

    [Fact]
    public void CreateHttpProviderOrThrow_throws_when_registry_empty()
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var req = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=orphan",
            rsa,
            System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var reg = new TimestampResponderRegistry();
        Assert.Throws<InvalidOperationException>(() => reg.CreateHttpProviderOrThrow(cert));
    }
}
