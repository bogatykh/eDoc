using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using eDocLib;
using eDocLib.Asic.Xades;
using eDocLib.Configuration;
using eDocLib.Validation;
using Xunit;

namespace eDocLib.Tests;

/// <summary>
/// LV EDOC 2.0: <see cref="SignatureTrustPolicy.ForLatvianEdocLtvWithDefaultTrustedListAsync"/> and
/// <see cref="Edoc.OpenAndValidateAsync"/> with <see cref="HttpClient"/> (HTTP mock, no live network).
/// </summary>
public class LatvianLtvTrustedListIntegrationTests
{
    private const string LatviaTslPublicationUrl = "https://trustlist.gov.lv/tsl/latvian-tsl.xml";

    private static string TslFixturePath(string fileName) =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "tsl", fileName);

    [Fact]
    public async Task ForLatvianEdocLtvWithDefaultTrustedListAsync_loads_lv_tsl_and_enables_gates()
    {
        var tslBytes = await File.ReadAllBytesAsync(TslFixturePath("minimal-qes-granted.xml"));
        var handler = new QueuedHttpMessageHandler();
        handler.Enqueue(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(tslBytes) });
        using var http = new HttpClient(handler);

        var config = EdocLibConfigBuilder.Create().Build();
        var policy = await SignatureTrustPolicy.ForLatvianEdocLtvWithDefaultTrustedListAsync(
            config,
            http,
            verifyTrustedListXmlSignature: false);

        Assert.NotNull(policy.TrustedListServiceIndex);
        Assert.True(policy.RequireQualifiedTimestampServiceType);
        Assert.True(policy.RequireSigningCertificateListedInTrustedList);
        Assert.Single(handler.RequestUris);
        Assert.Equal(LatviaTslPublicationUrl, handler.RequestUris[0]);
    }

    [Fact]
    public async Task ForLatvianEdocLtvWithDefaultTrustedListAsync_CreateDefault_uses_relay_prefix()
    {
        var tslBytes = await File.ReadAllBytesAsync(TslFixturePath("minimal-qes-granted.xml"));
        var handler = new QueuedHttpMessageHandler();
        handler.Enqueue(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(tslBytes) });
        using var http = new HttpClient(handler);

        var config = EdocLibConfigBuilder.CreateDefault().Build();
        _ = await SignatureTrustPolicy.ForLatvianEdocLtvWithDefaultTrustedListAsync(
            config,
            http,
            verifyTrustedListXmlSignature: false);

        Assert.Single(handler.RequestUris);
        var uri = handler.RequestUris[0];
        Assert.StartsWith("https://epout.eparaksts.lv/tsl-proxy/responder?uri=", uri, StringComparison.Ordinal);
        Assert.Contains(Uri.EscapeDataString(LatviaTslPublicationUrl), uri, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ForLatvianEdocLtvWithDefaultTrustedListAsync_throws_when_fetch_fails()
    {
        var handler = new QueuedHttpMessageHandler();
        handler.Enqueue(new HttpResponseMessage(HttpStatusCode.NotFound));
        using var http = new HttpClient(handler);

        var config = EdocLibConfigBuilder.Create().Build();
        await Assert.ThrowsAsync<HttpRequestException>(() =>
            SignatureTrustPolicy.ForLatvianEdocLtvWithDefaultTrustedListAsync(config, http, verifyTrustedListXmlSignature: false));
    }

    [Fact]
    public async Task OpenAndValidateAsync_with_HttpClient_fetches_tsl_then_validates_container()
    {
        var tslBytes = await File.ReadAllBytesAsync(TslFixturePath("minimal-qes-granted.xml"));
        var handler = new QueuedHttpMessageHandler();
        handler.Enqueue(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(tslBytes) });

        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(
            "CN=latvian-ltv-open",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(1));

        var payload = "ltv-open"u8.ToArray();
        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload), "doc.txt", "text/plain");
        edoc.AddSignature(
            XadesBesSigner.Sign(
                new[] { new DataFile(new MemoryStream(payload), "doc.txt", "text/plain") },
                cert,
                DateTimeOffset.UtcNow));

        using var zip = new MemoryStream();
        edoc.Save(zip);
        zip.Position = 0;

        using var http = new HttpClient(handler);
        var config = EdocLibConfigBuilder.Create().Build();
        var read = await Edoc.OpenAndValidateAsync(
            config,
            zip,
            http,
            verifyTrustedListXmlSignature: false);

        Assert.True(read.HasSignatures);
        Assert.False(read.AllSignaturesValid);
        Assert.Contains(
            "trusted service list",
            read.Signatures[0].Result.Error ?? "",
            StringComparison.OrdinalIgnoreCase);
    }
}
