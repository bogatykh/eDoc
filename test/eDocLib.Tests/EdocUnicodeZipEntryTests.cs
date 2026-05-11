using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib;
using eDocLib.Validation;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

public class EdocUnicodeZipEntryTests
{
    [Fact]
    public async Task Unicode_attachment_names_preserved_in_zip_round_trip()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=unicode-path", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "payload"u8.ToArray();
        var relativeName = "files/\u0417\u0430\u043C\u0435\u0442\u043A\u0430-\u9644\u4EF6.bin";
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), relativeName, "application/octet-stream") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2026-04-01T11:00:00Z"));

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), relativeName, "application/octet-stream");
        edoc.AddSignature(sig);

        using var zip = new MemoryStream();
        edoc.Save(zip);
        zip.Position = 0;

        var loaded = new Edoc(zip);
        Assert.Single(loaded.DataFiles);
        Assert.Equal(relativeName, loaded.DataFiles.First().Name);

        var report = await EdocValidation.ValidateSignaturesAsync(loaded, SignatureTrustPolicy.CryptographyOnly);
        Assert.True(report.AllSignaturesValid, report.Signatures[0].Result.Error);
    }
}
