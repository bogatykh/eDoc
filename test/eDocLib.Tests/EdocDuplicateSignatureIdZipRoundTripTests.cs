using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using eDocLib.Asic.Container;
using eDocLib.Asic.Manifest;
using eDocLib;
using eDocLib.Validation;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

/// <summary>
/// Same <c>ds:Signature/@Id</c> in two distinct META-INF XML files — ordering matches ZIP read order (first match wins).
/// </summary>
public class EdocDuplicateSignatureIdZipRoundTripTests
{
    [Fact]
    public void Two_signature_files_same_xml_id_resolve_and_validate_first()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=dup-zip-id", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "zip-dup"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var t = DateTimeOffset.Parse("2026-05-15T10:00:00Z");

        var sig = XadesBesSigner.Sign(dfs, cert, t, signatureId: "shared-id");
        var xmlUtf8 = Encoding.UTF8.GetBytes(Serialize(sig));

        var manifest = new OasisManifest();
        manifest.Add("doc.txt", "text/plain");

        // Two ZIP entries (signatures0 / signatures1): duplicate Id is still illegal in XML terms,
        // but here both files contain identical markup — models tooling that re-exported the same block twice.
        var zip = ZipTestHelpers.BuildMinimalAsicZip(
            manifest.Generate(),
            new Dictionary<string, byte[]> { ["doc.txt"] = payload.ToArray() },
            new List<byte[]> { xmlUtf8, xmlUtf8.ToArray() });

        using var ms = new MemoryStream(zip);
        var edoc = new Edoc(ms);

        Assert.Equal(2, edoc.Signatures.Count);
        Assert.True(edoc.TryResolveSignature("shared-id", out var resolved));
        Assert.Same(edoc.GetSignatureAt(0), resolved);

        var report = EdocValidation.ValidateSignatures(edoc, SignatureTrustPolicy.CryptographyOnly);
        Assert.Equal(2, report.Signatures.Count);
        Assert.True(report.Signatures[0].Result.Success, report.Signatures[0].Result.Error);
        Assert.True(report.Signatures[1].Result.Success, report.Signatures[1].Result.Error);
        Assert.True(report.AllSignaturesValid);
    }

    private static string Serialize(AsicSignature sig)
    {
        using var s = new MemoryStream();
        sig.WriteTo(s);
        return Encoding.UTF8.GetString(s.ToArray());
    }
}
