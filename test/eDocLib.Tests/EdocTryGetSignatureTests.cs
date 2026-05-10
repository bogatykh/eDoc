using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using eDocLib;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

/// <summary><see cref="Edoc.TryGetSignature"/> wraps only <see cref="XadesSignature"/> entries.</summary>
public class EdocTryGetSignatureTests
{
    [Fact]
    public void TryGetSignature_returns_false_for_RawXmlSignature_even_when_Id_matches()
    {
        var xml = new XmlDocument();
        xml.LoadXml(
            """
            <?xml version="1.0" encoding="UTF-8"?>
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#" Id="match-me">
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
        edoc.AddSignature(new RawXmlSignature(xml));

        Assert.False(edoc.TryGetSignature("match-me", out var info));
        Assert.Null(info);

        Assert.True(edoc.TryResolveSignature("match-me", out var raw));
        Assert.NotNull(raw);
        Assert.IsType<RawXmlSignature>(raw);
    }

    [Fact]
    public void TryGetSignature_returns_info_when_Xades_signature_present()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=tgs", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "p"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "z.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2026-12-10T12:00:00Z"),
            signatureId: "xades-by-id");

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "z.txt", "text/plain");
        edoc.AddSignature(sig);

        Assert.True(edoc.TryGetSignature("xades-by-id", out var info));
        Assert.NotNull(info);
        Assert.Equal("xades-by-id", info.Id);
    }
}
