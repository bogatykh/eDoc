using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using eDocLib;
using eDocLib.Validation;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

public class EdocMultiFileSigningTests
{
    [Fact]
    public async Task Three_payload_files_single_signature_round_trip_validates()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=multi-file", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var alpha = Encoding.UTF8.GetBytes("alpha-block");
        var beta = Encoding.UTF8.GetBytes("beta-block");
        var gamma = new byte[] { 0x00, 0x41, 0xFE, 0x88 };

        var dfs = new[]
        {
            new DataFile(new MemoryStream(alpha.ToArray()), "parts/alpha.bin", "application/octet-stream"),
            new DataFile(new MemoryStream(beta.ToArray()), "parts/beta.bin", "application/octet-stream"),
            new DataFile(new MemoryStream(gamma.ToArray()), "gamma.raw", "application/octet-stream"),
        };

        var t = DateTimeOffset.Parse("2026-03-15T09:30:00Z");
        var sig = XadesBesSigner.Sign(dfs, cert, t, signatureId: "sig-bundle");

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(alpha.ToArray()), "parts/alpha.bin", "application/octet-stream");
        edoc.AddDataFile(new MemoryStream(beta.ToArray()), "parts/beta.bin", "application/octet-stream");
        edoc.AddDataFile(new MemoryStream(gamma.ToArray()), "gamma.raw", "application/octet-stream");
        edoc.AddSignature(sig);

        using var zip = new MemoryStream();
        edoc.Save(zip);
        zip.Position = 0;

        var report = await EdocValidation.OpenAndValidateAsync(zip, SignatureTrustPolicy.CryptographyOnly);
        Assert.True(report.AllSignaturesValid, report.Signatures.Count > 0 ? report.Signatures[0].Result.Error : "no sig");
    }
}
