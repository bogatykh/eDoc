using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using eDocLib;
using eDocLib.Asic.Container;
using eDocLib.Asic.Manifest;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

/// <summary>Manifest <c>full-path</c> must match ZIP entry names (no implicit <c>./</c> normalization).</summary>
public class AsicManifestPathVsZipEntryTests
{
    [Fact]
    public void Manifest_full_path_with_dot_slash_prefix_does_not_match_plain_zip_entry_name_on_load()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=dot", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "dot"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2026-06-02T08:00:00Z"));
        var sigUtf8 = Encoding.UTF8.GetBytes(SerializeSig(sig));

        var manifest = new OasisManifest();
        manifest.Add("./doc.txt", "text/plain");

        var zip = ZipTestHelpers.BuildMinimalAsicZip(
            manifest.Generate(),
            new Dictionary<string, byte[]> { ["doc.txt"] = payload.ToArray() },
            new List<byte[]> { sigUtf8 });

        var ex = Assert.Throws<AsicException>(() => new Edoc(new MemoryStream(zip)));
        Assert.Contains("doc.txt", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("not listed", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    private static string SerializeSig(AsicSignature sig)
    {
        using var s = new MemoryStream();
        sig.WriteTo(s);
        return Encoding.UTF8.GetString(s.ToArray());
    }
}
