using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using eDocLib;
using eDocLib.Asic.Container;
using eDocLib.Asic.Manifest;
using eDocLib.Configuration;
using eDocLib.Validation;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

/// <summary>
/// Opening large payloads (spill), and malformed / crowded XML signature documents — synthetic only.
/// </summary>
public class AsicContainerOpenAndSignatureDocumentTests
{
    [Fact]
    public void Empty_SignatureValue_element_throws_CryptographicException_on_validate()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=empty-sv", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "p"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2026-05-12T08:00:00Z"));

        var xml = SerializeSignature(sig);
        var doc = new XmlDocument { PreserveWhitespace = false };
        doc.LoadXml(xml);
        var nsmgr = new XmlNamespaceManager(doc.NameTable);
        nsmgr.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
        var sv = doc.SelectSingleNode("//ds:SignatureValue", nsmgr) as XmlElement
                 ?? throw new InvalidOperationException("SignatureValue missing.");
        sv.InnerText = string.Empty;

        var manifest = new OasisManifest();
        manifest.Add("doc.txt", "text/plain");

        var zip = ZipTestHelpers.BuildMinimalAsicZip(
            manifest.Generate(),
            new Dictionary<string, byte[]> { ["doc.txt"] = payload.ToArray() },
            new List<byte[]> { Encoding.UTF8.GetBytes(doc.OuterXml) });

        Assert.Throws<CryptographicException>(() =>
            EdocValidation.OpenAndValidate(new MemoryStream(zip), SignatureTrustPolicy.CryptographyOnly));
    }

    [Fact]
    public void Signature_xml_without_KeyInfo_fails_with_missing_signing_certificate_message()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=no-keyinfo", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "k"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2026-05-12T09:00:00Z"));

        var doc = new XmlDocument { PreserveWhitespace = false };
        doc.LoadXml(SerializeSignature(sig));
        var nsmgr = new XmlNamespaceManager(doc.NameTable);
        nsmgr.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
        var ki = doc.SelectSingleNode("//ds:KeyInfo", nsmgr);
        Assert.NotNull(ki);
        ki.ParentNode!.RemoveChild(ki);

        var manifest = new OasisManifest();
        manifest.Add("doc.txt", "text/plain");

        var zip = ZipTestHelpers.BuildMinimalAsicZip(
            manifest.Generate(),
            new Dictionary<string, byte[]> { ["doc.txt"] = payload.ToArray() },
            new List<byte[]> { Encoding.UTF8.GetBytes(doc.OuterXml) });

        var report = EdocValidation.OpenAndValidate(new MemoryStream(zip), SignatureTrustPolicy.CryptographyOnly);
        Assert.False(report.AllSignaturesValid);
        Assert.Contains(
            "Signing certificate is missing",
            report.Signatures[0].Result.Error ?? string.Empty,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// Reader attaches one <see cref="AsicSignature"/> per ZIP entry using the first <c>ds:Signature</c> in the document.
    /// A second sibling <c>ds:Signature</c> remains in the DOM and breaks XML-DSig canonicalisation here — verification throws.
    /// </summary>
    [Fact]
    public void Two_ds_Signature_elements_in_one_xml_first_is_wrapped_verify_throws()
    {
        using var rsa1 = RSA.Create(2048);
        using var rsa2 = RSA.Create(2048);
        var req1 = new CertificateRequest("CN=sig-a", rsa1, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var req2 = new CertificateRequest("CN=sig-b", rsa2, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert1 = req1.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        using var cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "shared"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var t = DateTimeOffset.Parse("2026-05-12T10:00:00Z");

        var sig1 = XadesBesSigner.Sign(dfs, cert1, t, signatureId: "sig-first");
        var sig2 = XadesBesSigner.Sign(dfs, cert2, t, signatureId: "sig-second");

        var d1 = new XmlDocument { PreserveWhitespace = false };
        d1.LoadXml(SerializeSignature(sig1));
        var d2 = new XmlDocument { PreserveWhitespace = false };
        d2.LoadXml(SerializeSignature(sig2));

        var pack = new XmlDocument();
        var root = pack.CreateElement("SignatureBundle");
        pack.AppendChild(root);
        root.AppendChild(pack.ImportNode(d1.DocumentElement!, deep: true));
        root.AppendChild(pack.ImportNode(d2.DocumentElement!, deep: true));

        var manifest = new OasisManifest();
        manifest.Add("doc.txt", "text/plain");

        var zip = ZipTestHelpers.BuildMinimalAsicZip(
            manifest.Generate(),
            new Dictionary<string, byte[]> { ["doc.txt"] = payload.ToArray() },
            new List<byte[]> { Encoding.UTF8.GetBytes(pack.OuterXml) });

        using var edoc = new Edoc(new MemoryStream(zip));
        Assert.Single(edoc.Signatures);
        var only = Assert.IsType<AsicSignature>(edoc.Signatures.First());
        Assert.Equal("sig-first", only.Id);

        Assert.Throws<CryptographicException>(() =>
            EdocValidation.ValidateSignatures(edoc, SignatureTrustPolicy.CryptographyOnly));
    }

    [Fact]
    public void Oversized_payload_entry_uses_spill_directory_and_still_validates()
    {
        const int payloadLen = 512 * 1024;
        var payload = new byte[payloadLen];
        for (var i = 0; i < payloadLen; i++)
        {
            payload[i] = (byte)((i * 13 + 7) % 251);
        }

        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=spill", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "heavy.bin", "application/octet-stream") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2026-05-12T11:00:00Z"));

        using var saved = new MemoryStream();
        var builder = Edoc.CreateNew();
        builder.AddDataFile(new MemoryStream(payload.ToArray()), "heavy.bin", "application/octet-stream");
        builder.AddSignature(sig);
        builder.Save(saved);
        saved.Position = 0;

        var spillDir = Path.Combine(Path.GetTempPath(), "eDocLibTests-spill-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(spillDir);
        try
        {
            var cfg = EdocLibConfigBuilder.Create()
                .WithPayloadMemoryThresholdBytes(64 * 1024)
                .WithPayloadSpillTempDirectory(spillDir)
                .Build();

            saved.Position = 0;
            var report = Edoc.OpenAndValidate(cfg, saved, SignatureTrustPolicy.CryptographyOnly);
            try
            {
                var df = report.Edoc.DataFiles.First();
                Assert.Equal("heavy.bin", df.Name);
                Assert.IsAssignableFrom<FileStream>(df.Stream);
                Assert.True(report.AllSignaturesValid, report.Signatures.ElementAtOrDefault(0)?.Result.Error);
            }
            finally
            {
                report.Edoc.Dispose();
            }
        }
        finally
        {
            try
            {
                Directory.Delete(spillDir, recursive: true);
            }
            catch
            {
                // Best-effort cleanup (file may still be delete-on-close).
            }
        }
    }

    private static string SerializeSignature(ISignature sig)
    {
        using var ms = new MemoryStream();
        sig.WriteTo(ms);
        return Encoding.UTF8.GetString(ms.ToArray());
    }
}
