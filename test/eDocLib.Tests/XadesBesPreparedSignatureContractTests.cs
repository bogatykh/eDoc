using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib;
using eDocLib.Validation;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

/// <summary>Contracts for <see cref="XadesBesPreparedSignature.Complete"/>.</summary>
public class XadesBesPreparedSignatureContractTests
{
    [Fact]
    public void Complete_empty_signature_octets_throws_ArgumentException()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=prep-complete", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var publicOnly = new X509Certificate2(cert.Export(X509ContentType.Cert));

        var prep = XadesBesSigner.PrepareSign(
            new[] { new DataFile(new MemoryStream("x"u8.ToArray()), "f.txt", "text/plain") },
            publicOnly,
            DateTimeOffset.Parse("2026-12-14T10:00:00Z"));

        var ex = Assert.Throws<ArgumentException>(() => prep.Complete(ReadOnlySpan<byte>.Empty));
        Assert.Equal("signatureValueOctets", ex.ParamName);
    }

    [Fact]
    public void Complete_with_short_random_octets_fails_rsa_signature_verification()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=bad-sig-bytes", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var publicOnly = new X509Certificate2(cert.Export(X509ContentType.Cert));

        var payload = "sign-me"u8.ToArray();
        var prep = XadesBesSigner.PrepareSign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "blob.bin", "application/octet-stream") },
            publicOnly,
            DateTimeOffset.Parse("2026-12-18T09:00:00Z"));

        var garbage = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };
        var broken = prep.Complete(garbage);

        Assert.False(
            DetachedSignatureVerifier.TryVerify(
                broken,
                new Dictionary<string, byte[]> { ["blob.bin"] = payload },
                out var err),
            err);
        Assert.False(string.IsNullOrEmpty(err));
        Assert.Contains("RSA", err, StringComparison.OrdinalIgnoreCase);
    }
}
