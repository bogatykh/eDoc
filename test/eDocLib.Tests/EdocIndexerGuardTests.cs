using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

/// <summary>Bounds checking on <see cref="Edoc"/> / <see cref="Asic.AsicContainer"/> index accessors.</summary>
public class EdocIndexerGuardTests
{
    [Fact]
    public void GetDataFileAt_throws_when_empty()
    {
        var edoc = Edoc.CreateNew();
        Assert.Throws<ArgumentOutOfRangeException>(() => edoc.GetDataFileAt(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => edoc.GetDataObject(0));
    }

    [Fact]
    public void GetSignatureAt_throws_when_empty()
    {
        var edoc = Edoc.CreateNew();
        Assert.Throws<ArgumentOutOfRangeException>(() => edoc.GetSignatureAt(0));
    }

    [Fact]
    public void TryResolveSignature_empty_id_returns_false_whitespace_searches_literal()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=id-guard", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "q"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2026-12-08T12:00:00Z"),
            signatureId: "real-id");

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
        edoc.AddSignature(sig);

        Assert.False(edoc.TryResolveSignature("", out _));
        Assert.False(edoc.TryResolveSignature("   ", out _));
        Assert.True(edoc.TryResolveSignature("real-id", out var resolved));
        Assert.NotNull(resolved);
    }
}
