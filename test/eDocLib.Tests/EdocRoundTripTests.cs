using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using eDocLib.Asic.Container;
using eDocLib.Validation;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib;

public class EdocRoundTripTests
{
    [Fact]
    public async Task RawXmlSignature_round_trips_through_container()
    {
        var xml = new XmlDocument();
        xml.LoadXml(
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
        edoc.AddSignature(new RawXmlSignature(xml));

        using var ms = new MemoryStream();
        edoc.Save(ms);
        ms.Position = 0;

        var read = new Edoc(ms);
        Assert.Single(read.Signatures);
        Assert.Null(read.Signatures.First().SigningCertificate);
        using var echoed = new MemoryStream();
        read.Signatures.First().WriteTo(echoed);
        Assert.True(echoed.Length > 50);
    }

    [Fact]
    public async Task XadesBes_sign_verify_and_edoc_round_trip()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=eDoc test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "hello eDoc"u8.ToArray();
        var dataFiles = new[]
        {
            new DataFile(new MemoryStream(payload), "doc.txt", "text/plain"),
        };

        var sig = XadesBesSigner.Sign(dataFiles, cert, DateTimeOffset.Parse("2024-01-15T12:00:00Z"));

        Assert.True(DetachedSignatureVerifier.TryVerify(sig, new Dictionary<string, byte[]>
        {
            ["doc.txt"] = payload,
        }, out var err), err);

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload), "doc.txt", "text/plain");
        edoc.AddSignature(sig);

        using var zip = new MemoryStream();
        edoc.Save(zip);
        zip.Position = 0;

        var loaded = new Edoc(zip);
        Assert.Single(loaded.Signatures);
        var roundSig = Assert.IsType<AsicSignature>(loaded.Signatures.First());

        using var sigXmlAfter = new MemoryStream();
        roundSig.WriteTo(sigXmlAfter);
        using var sigXmlBefore2 = new MemoryStream();
        sig.WriteTo(sigXmlBefore2);
        Assert.Equal(sigXmlBefore2.ToArray(), sigXmlAfter.ToArray());

        Assert.True(DetachedSignatureVerifier.TryVerify(roundSig, new Dictionary<string, byte[]>
        {
            ["doc.txt"] = payload,
        }, out err), err);

        var chainPolicy = new SignatureTrustPolicy
        {
            ValidateCertificateChain = true,
            RevocationMode = X509RevocationMode.NoCheck,
            CustomTrustAnchors = new X509Certificate2Collection(cert),
        };
        var validated = await SignatureValidator.ValidateAsync(roundSig, new Dictionary<string, byte[]>
        {
            ["doc.txt"] = payload,
        }, chainPolicy);
        Assert.True(validated.Success, validated.Error);
        Assert.True(validated.CertificateChainValid);

        zip.Position = 0;
        var report = await EdocValidation.OpenAndValidateAsync(zip, chainPolicy);
        Assert.True(report.AllSignaturesValid);
        Assert.Single(report.Signatures);
        Assert.True(report.Signatures[0].Result.Success);

        zip.Position = 0;
        var readAgain = await EdocValidation.OpenAndValidateAsync(zip, chainPolicy);
        var docReport = readAgain.BuildValidationReport(chainPolicy);
        Assert.True(docReport.AllSignaturesValid);
        Assert.Equal(global::eDocLib.Validation.Reporting.ValidationType.Root, docReport.Root.Type);
        Assert.Single(docReport.Signatures);
        Assert.Equal(global::eDocLib.Validation.Reporting.ValidationType.Signature, docReport.Signatures[0].Tree.Type);
        Assert.Equal(SignatureValidationIndication.TotalPassed, docReport.Signatures[0].Indication);
    }

    [Fact]
    public async Task ValidateSignatures_rejects_RawXmlSignature_as_unsupported_for_crypto()
    {
        var xml = new XmlDocument();
        xml.LoadXml(
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
        edoc.AddSignature(new RawXmlSignature(xml));

        var report = await EdocValidation.ValidateSignaturesAsync(edoc);
        Assert.Single(report.Signatures);
        Assert.False(report.Signatures[0].Result.Success);
        Assert.Contains("does not support", report.Signatures[0].Result.Error ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }
}
