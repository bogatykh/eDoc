using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib;
using eDocLib.Validation;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

/// <summary>Digest failures when stored bytes differ from signed payload (via <see cref="EdocValidation"/>).</summary>
public class EdocValidationPayloadMismatchTests
{
    [Fact]
    public async Task Payload_bytes_swapped_after_sign_fails_validation_same_mime_and_name()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=tamper", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var signedBytes = "signed-version\n"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(signedBytes.ToArray()), "note.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2026-12-03T12:00:00Z"));

        var tampered = "tampered-version\n"u8.ToArray();
        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(tampered.ToArray()), "note.txt", "text/plain");
        edoc.AddSignature(sig);

        using var zip = new MemoryStream();
        edoc.Save(zip);
        zip.Position = 0;

        var report = await EdocValidation.OpenAndValidateAsync(zip, SignatureTrustPolicy.CryptographyOnly);
        Assert.False(report.AllSignaturesValid);
        Assert.Contains("Digest mismatch", report.Signatures[0].Result.Error ?? string.Empty, StringComparison.Ordinal);
    }
}
