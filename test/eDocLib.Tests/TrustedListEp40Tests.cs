using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using eDocLib.Trust.Tsl;
using eDocLib.Validation;
using Xunit;

namespace eDocLib.Tests;

public class TrustedListEp40Tests
{
    private static byte[] MinimalSignedTslXmlBytes()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=EP-40 TSL", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var tslSigner = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(
            """
            <?xml version="1.0" encoding="UTF-8"?>
            <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
              <SchemeInformation>
                <TSLSequenceNumber>1</TSLSequenceNumber>
                <SchemeTerritory>LV</SchemeTerritory>
                <ListIssueDateTime>2024-01-01T00:00:00Z</ListIssueDateTime>
              </SchemeInformation>
              <TrustServiceProviderList/>
            </TrustServiceStatusList>
            """);

        var signedXml = new SignedXml(doc);
        signedXml.SigningKey = tslSigner.GetRSAPrivateKey();
        var reference = new Reference { Uri = "" };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        signedXml.AddReference(reference);
        var keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(tslSigner));
        signedXml.KeyInfo = keyInfo;
        signedXml.ComputeSignature();
        var sigEl = signedXml.GetXml();
        doc.DocumentElement!.AppendChild(doc.ImportNode(sigEl, deep: true));

        using var ms = new MemoryStream();
        doc.Save(ms);
        return ms.ToArray();
    }

    [Fact]
    public void TrustedListReader_TryLoad_returns_TrustedListLoadResult_bundle()
    {
        var bytes = MinimalSignedTslXmlBytes();
        using var s = new MemoryStream(bytes);
        Assert.True(TrustedListReader.TryLoadDocument(s, verifyXmlSignature: true, out TrustedListLoadResult? bundle, out var err), err);
        Assert.NotNull(bundle);
        Assert.Equal("LV", bundle.DocumentMetadata.SchemeTerritory);
        Assert.NotNull(bundle.Index);
    }

    [Fact]
    public void TrustedListValidator_and_TrustedListParser_delegate_to_same_load()
    {
        var bytes = MinimalSignedTslXmlBytes();
        using (var s = new MemoryStream(bytes))
        {
            Assert.True(TrustedListValidator.TryValidate(s, true, out var v, out var e1), e1);
            Assert.NotNull(v);
        }

        using (var s = new MemoryStream(bytes))
        {
            Assert.True(TrustedListParser.TryParse(s, true, out var p, out var e2), e2);
            Assert.NotNull(p);
        }
    }

    [Fact]
    public async Task TrustedListManager_LoadAsync_round_trips_provider()
    {
        var bytes = MinimalSignedTslXmlBytes();
        var handler = new HttpMock(() => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(bytes),
        });
        using var http = new HttpClient(handler);
        var provider = new HttpTslTrustedListProvider(http);
        var mgr = new TrustedListManager(provider);

        var (result, error) = await mgr.LoadAsync("https://mock-tsl.ep40.test/list.xml", verifyXmlSignature: true);
        Assert.Null(error);
        Assert.NotNull(result);
        Assert.Equal("LV", result.DocumentMetadata.SchemeTerritory);
        Assert.Single(handler.RequestUris);
    }

    private sealed class HttpMock : HttpMessageHandler
    {
        private readonly Func<HttpResponseMessage> _factory;
        internal List<string> RequestUris { get; } = new();

        public HttpMock(Func<HttpResponseMessage> factory) => _factory = factory;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestUris.Add(request.RequestUri!.ToString());
            return Task.FromResult(_factory());
        }
    }
}
