using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib;
using eDocLib.Validation;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

/// <summary><see cref="Edoc.Save(System.IO.Stream,bool,eDocLib.Validation.SignatureTrustPolicy?)"/> preflight branch.</summary>
public class EdocSavePreflightTests
{
    [Fact]
    public void Save_with_preflight_true_and_no_signatures_does_not_throw()
    {
        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream("only-data"u8.ToArray()), "plain.txt", "text/plain");

        using var ms = new MemoryStream();
        edoc.Save(ms, validateSignaturesFirst: true);
        Assert.True(ms.Length > 0);
    }

    [Fact]
    public void Save_with_preflight_true_and_valid_signature_succeeds()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=preflight-ok", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "ok-bytes"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2026-12-11T09:00:00Z"));

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
        edoc.AddSignature(sig);

        using var ms = new MemoryStream();
        edoc.Save(ms, validateSignaturesFirst: true, SignatureTrustPolicy.CryptographyOnly);
        ms.Position = 0;

        var report = EdocValidation.OpenAndValidate(ms, SignatureTrustPolicy.CryptographyOnly);
        Assert.True(report.AllSignaturesValid);
    }
}
