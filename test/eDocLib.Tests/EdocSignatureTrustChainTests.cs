using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib;
using eDocLib.Validation;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

/// <summary>
/// PKIX chain branch of <see cref="SignatureTrustPolicy"/> on real <see cref="Edoc"/> validation (self-signed fixtures).
/// </summary>
public class EdocSignatureTrustChainTests
{
    [Fact]
    public async Task ValidateCertificateChain_without_trust_anchor_fails_for_self_signed_signer()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=self-chain-fail", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "chain-fail"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2026-05-15T11:00:00Z"));

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
        edoc.AddSignature(sig);

        using var zip = new MemoryStream();
        edoc.Save(zip);
        zip.Position = 0;

        var policy = new SignatureTrustPolicy
        {
            ValidateCertificateChain = true,
            RevocationMode = X509RevocationMode.NoCheck,
        };

        var report = await EdocValidation.OpenAndValidateAsync(zip, policy);
        Assert.False(report.AllSignaturesValid);
        Assert.False(report.Signatures[0].Result.Success);
        Assert.Contains("chain", report.Signatures[0].Result.Error ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ValidateCertificateChain_with_custom_anchor_succeeds_for_same_self_signed_signer()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=self-chain-ok", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "chain-ok"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2026-05-15T12:00:00Z"));

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
        edoc.AddSignature(sig);

        using var zip = new MemoryStream();
        edoc.Save(zip);
        zip.Position = 0;

        using var anchor = new X509Certificate2(cert.Export(X509ContentType.Cert));
        var policy = new SignatureTrustPolicy
        {
            ValidateCertificateChain = true,
            RevocationMode = X509RevocationMode.NoCheck,
            CustomTrustAnchors = new X509Certificate2Collection(anchor),
        };

        var report = await EdocValidation.OpenAndValidateAsync(zip, policy);
        Assert.True(report.AllSignaturesValid, report.Signatures.ElementAtOrDefault(0)?.Result.Error);
    }
}
