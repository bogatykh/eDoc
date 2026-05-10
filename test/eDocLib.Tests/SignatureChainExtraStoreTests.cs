using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using eDocLib.Validation;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib;

/// <summary>Signer PKIX path uses <see cref="SignatureTrustPolicy.ExtraChainCertificates"/> (e.g. from TSL).</summary>
public class SignatureChainExtraStoreTests
{
    [Fact]
    public void Edoc_validate_succeeds_when_sub_ca_only_in_extra_store_from_tsl_xml()
    {
        using var rootRsa = RSA.Create(2048);
        var rootReq = new CertificateRequest("CN=Root", rootRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, false));
        rootReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootReq.PublicKey, false));
        using var root = rootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddYears(10));

        using var subRsa = RSA.Create(2048);
        var subReq = new CertificateRequest("CN=Sub CA", subRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        subReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        subReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, false));
        subReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(subReq.PublicKey, false));
        var subSerial = new byte[8];
        RandomNumberGenerator.Fill(subSerial);
        using var subPub = subReq.Create(root, DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddYears(5), subSerial);
        using var sub = subPub.CopyWithPrivateKey(subRsa);

        using var leafRsa = RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=Leaf", leafRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        var leafSerial = new byte[8];
        RandomNumberGenerator.Fill(leafSerial);
        using var leafPub = leafReq.Create(sub, DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddYears(1), leafSerial);
        using var leaf = leafPub.CopyWithPrivateKey(leafRsa);

        var tslXml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
              <X509Certificate>{Convert.ToBase64String(sub.Export(X509ContentType.Cert))}</X509Certificate>
              <X509Certificate>{Convert.ToBase64String(root.Export(X509ContentType.Cert))}</X509Certificate>
            </TrustServiceStatusList>
            """;

        var tslExtra = TrustedListCertificateParser.ReadCertificates(new MemoryStream(Encoding.UTF8.GetBytes(tslXml)));

        var payload = "chain-extra"u8.ToArray();
        var dataFiles = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dataFiles, leaf, DateTimeOffset.Parse("2024-06-01T12:00:00Z"));

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
        edoc.AddSignature(sig);

        using var zip = new MemoryStream();
        edoc.Save(zip);
        zip.Position = 0;

        var policy = new SignatureTrustPolicy
        {
            ValidateCertificateChain = true,
            RevocationMode = X509RevocationMode.NoCheck,
            CustomTrustAnchors = new X509Certificate2Collection(root),
            ExtraChainCertificates = tslExtra,
        };

        try
        {
            var report = EdocValidation.OpenAndValidate(zip, policy);
            Assert.True(report.AllSignaturesValid, report.Signatures[0].Result.Error);
            Assert.True(report.Signatures[0].Result.CertificateChainValid);
            var chain = report.Signatures[0].Result.SignerCertificateChain;
            Assert.NotNull(chain);
            Assert.Equal(3, chain!.Count);
            Assert.Contains("CN=Leaf", chain[0].Subject, StringComparison.Ordinal);
            Assert.Equal(leaf.Thumbprint, chain[0].Thumbprint);
            Assert.Contains("CN=Sub CA", chain[1].Subject, StringComparison.Ordinal);
            Assert.Contains("CN=Root", chain[2].Subject, StringComparison.Ordinal);
        }
        finally
        {
            foreach (X509Certificate2 c in tslExtra)
                c.Dispose();
        }
    }
}
