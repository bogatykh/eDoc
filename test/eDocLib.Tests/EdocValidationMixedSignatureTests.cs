using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using eDocLib;
using eDocLib.Validation;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

/// <summary><see cref="EdocValidation.ValidateSignatures"/> with heterogeneous <see cref="ISignature"/> kinds.</summary>
public class EdocValidationMixedSignatureTests
{
    [Fact]
    public async Task Mixed_Xades_and_raw_xml_signature_reports_each_and_overall_invalid()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=mixed", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "mixed-body"u8.ToArray();
        var goodSig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2026-12-06T15:00:00Z"),
            signatureId: "good");

        var rawXml = new XmlDocument();
        rawXml.LoadXml(
            """
            <?xml version="1.0" encoding="UTF-8"?>
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
                <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
                <Reference URI="">
                  <Transforms>
                    <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                  </Transforms>
                  <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                  <DigestValue>YWJj</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>dGVzdA==</SignatureValue>
            </Signature>
            """);

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
        edoc.AddSignature(goodSig);
        edoc.AddSignature(new RawXmlSignature(rawXml));

        var report = await EdocValidation.ValidateSignaturesAsync(edoc);
        Assert.Equal(2, report.Signatures.Count);
        Assert.False(report.AllSignaturesValid);
        Assert.True(report.Signatures[0].Result.Success);
        Assert.False(report.Signatures[1].Result.Success);
    }
}
