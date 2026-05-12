using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using eDocLib;
using eDocLib.Trust.Tsl;
using eDocLib.Validation;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

/// <summary>
/// V-05 (checklist §3): <see cref="HttpMessageHandler"/> mock serves signed TSL XML →
/// <see cref="HttpTslTrustedListProvider"/> → <see cref="TrustedListReader"/> →
/// <see cref="SignatureValidator"/> with <see cref="SignatureTrustPolicy.TrustedListServiceIndex"/>.
/// </summary>
public class TslHttpMockTrustedListPipelineTests
{
    [Fact]
    public async Task Http_mock_signed_tsl_fetch_TrustedListReader_SignatureValidator_records_qualification()
    {
        const string tslUrl = "https://mock-tsl.edoc.test/lv-trusted-list.xml";

        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=V05 pipeline TSL", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var listedSignerCert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var b64 = Convert.ToBase64String(listedSignerCert.Export(X509ContentType.Cert));
        const string typeId = TslQualificationMapper.ServiceTypeQCertESign;

        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(
            $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
              <TSPService>
                <ServiceInformation>
                  <ServiceTypeIdentifier>{typeId}</ServiceTypeIdentifier>
                  <ServiceStatus>{TslQualificationMapper.ServiceStatusGranted}</ServiceStatus>
                  <ServiceDigitalIdentity>
                    <DigitalId><X509Certificate>{b64}</X509Certificate></DigitalId>
                  </ServiceDigitalIdentity>
                </ServiceInformation>
              </TSPService>
            </TrustServiceStatusList>
            """);

        var signedXml = new SignedXml(doc);
        signedXml.SigningKey = listedSignerCert.GetRSAPrivateKey();
        var reference = new Reference { Uri = "" };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        signedXml.AddReference(reference);
        var keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(listedSignerCert));
        signedXml.KeyInfo = keyInfo;
        signedXml.ComputeSignature();
        var sigEl = signedXml.GetXml();
        doc.DocumentElement!.AppendChild(doc.ImportNode(sigEl, deep: true));

        using var tslMs = new MemoryStream();
        doc.Save(tslMs);
        var tslBytes = tslMs.ToArray();

        var handler = new QueuedHttpMessageHandler();
        handler.Enqueue(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(tslBytes),
        });
        using var http = new HttpClient(handler);
        var provider = new HttpTslTrustedListProvider(http);

        await using var fetched = await provider.GetTrustedListAsync(tslUrl);
        Assert.True(
            TrustedListReader.TryLoad(fetched, verifyXmlSignature: true, out var index, out var readErr),
            readErr);
        Assert.NotNull(index);
        Assert.Single(handler.RequestUris);
        Assert.Equal(tslUrl, handler.RequestUris[0]);

        var payload = "v05-tsl-pipeline"u8.ToArray();
        var dataFiles = new[] { new DataFile(new MemoryStream(payload), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dataFiles, listedSignerCert, DateTimeOffset.Parse("2024-06-01T10:00:00Z"));

        var policy = new SignatureTrustPolicy
        {
            ValidateCertificateChain = false,
            TrustedListServiceIndex = index,
        };
        var result = await SignatureValidator.ValidateAsync(sig, new Dictionary<string, byte[]> { ["doc.txt"] = payload }, policy);
        Assert.True(result.Success, result.Error);
        Assert.True(result.SigningCertificateListedInTrustedList);
        Assert.Contains(typeId, result.TrustedListServiceTypeIdentifiers!, StringComparer.OrdinalIgnoreCase);
        Assert.True(result.TrustedListQualificationIndicators!.SuggestsQualifiedElectronicSignature);
    }
}
