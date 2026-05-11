using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib;
using eDocLib.Validation;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

public class EdocPayloadExtentSigningTests
{
    [Fact]
    public async Task Zero_byte_payload_still_signs_and_verifies()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=empty-payload", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var empty = Array.Empty<byte>();
        var dfs = new[] { new DataFile(new MemoryStream(empty), "empty.dat", "application/octet-stream") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2026-05-02T08:00:00Z"));

        Assert.True(
            DetachedSignatureVerifier.TryVerify(sig, new Dictionary<string, byte[]> { ["empty.dat"] = empty }, out var err),
            err);

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(empty), "empty.dat", "application/octet-stream");
        edoc.AddSignature(sig);

        using var zip = new MemoryStream();
        edoc.Save(zip);
        zip.Position = 0;
        var report = await EdocValidation.OpenAndValidateAsync(zip, SignatureTrustPolicy.CryptographyOnly);
        Assert.True(report.AllSignaturesValid, report.Signatures[0].Result.Error);
    }

    [Fact]
    public async Task Medium_sized_payload_deterministic_pattern_round_trip()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=large-ish", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        const int length = 393_216;
        var blob = new byte[length];
        for (var i = 0; i < blob.Length; i++)
        {
            blob[i] = (byte)((i * 1315423911) ^ (i >> 3));
        }

        var dfs = new[] { new DataFile(new MemoryStream(blob), "bulk.dat", "application/octet-stream") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2026-08-01T00:00:00Z"));

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(blob.ToArray()), "bulk.dat", "application/octet-stream");
        edoc.AddSignature(sig);

        using var zip = new MemoryStream();
        edoc.Save(zip);
        zip.Position = 0;

        var report = await EdocValidation.OpenAndValidateAsync(zip, SignatureTrustPolicy.CryptographyOnly);
        Assert.True(report.AllSignaturesValid, report.Signatures[0].Result.Error);
    }
}
