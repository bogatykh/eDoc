using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

/// <summary><see cref="Edoc.Edoc(System.IO.Stream)"/> expects the stream position at the start of the ZIP.</summary>
public class EdocZipStreamPositionTests
{
    [Fact]
    public void Constructor_with_non_zero_stream_position_throws_or_fails_read()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=zip-pos", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "pos"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2026-12-16T08:00:00Z"));

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
        edoc.AddSignature(sig);

        using var zip = new MemoryStream();
        edoc.Save(zip);
        var bytes = zip.ToArray();

        using var skewed = new MemoryStream(bytes);
        skewed.Position = Math.Min(5, skewed.Length);

        Assert.ThrowsAny<Exception>(() => new Edoc(skewed));
    }
}
