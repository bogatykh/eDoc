using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib;
using eDocLib.Validation;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

/// <summary>
/// Validation outcomes after changing container contents relative to the detached signature.
/// Extra payload files not referenced by <c>ds:Reference</c> do not by themselves fail cryptographic verification here.
/// </summary>
public class EdocContainerMutationValidationTests
{
    [Fact]
    public async Task After_signing_add_extra_payload_signature_check_still_passes()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=drift", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var original = "original-bytes"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(original.ToArray()), "doc.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2026-06-01T15:00:00Z"));

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(original.ToArray()), "doc.txt", "text/plain");
        edoc.AddSignature(sig);
        edoc.AddDataFile(new MemoryStream("extra"u8.ToArray()), "extra.txt", "text/plain");

        using var zip = new MemoryStream();
        edoc.Save(zip);
        zip.Position = 0;

        var report = await EdocValidation.OpenAndValidateAsync(zip, SignatureTrustPolicy.CryptographyOnly);
        Assert.True(report.AllSignaturesValid, report.Signatures[0].Result.Error);
    }

    [Fact]
    public async Task Manifest_mime_can_differ_from_signing_time_label_without_breaking_digest_checks()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=mime-drift", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "same-bytes"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "note.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2026-07-20T10:10:00Z"));

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "note.txt", "application/octet-stream");
        edoc.AddSignature(sig);

        using var zip = new MemoryStream();
        edoc.Save(zip);
        zip.Position = 0;

        var report = await EdocValidation.OpenAndValidateAsync(zip, SignatureTrustPolicy.CryptographyOnly);
        Assert.True(report.AllSignaturesValid, report.Signatures[0].Result.Error);
    }

    [Fact]
    public async Task Removing_signed_payload_invalidates_validation()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=strip", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "keep-me"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "only.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2026-09-09T09:09:00Z"));

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "only.txt", "text/plain");
        edoc.AddSignature(sig);
        edoc.RemoveDataObjectAt(0);

        using var zip = new MemoryStream();
        edoc.Save(zip);
        zip.Position = 0;

        var report = await EdocValidation.OpenAndValidateAsync(zip, SignatureTrustPolicy.CryptographyOnly);
        Assert.False(report.AllSignaturesValid);
    }
}
