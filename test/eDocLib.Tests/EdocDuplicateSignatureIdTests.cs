using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

/// <summary>
/// When several <see cref="ISignature"/> entries share the same <see cref="ISignature.Id"/>,
/// <see cref="IContainer.TryResolveSignature"/> resolves the first match (ordering matters).
/// </summary>
public class EdocDuplicateSignatureIdTests
{
    [Fact]
    public void TryResolveSignature_returns_first_when_duplicate_ids()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=dup-id", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "dup"u8.ToArray();
        var t = DateTimeOffset.Parse("2026-12-13T12:00:00Z");

        var sigFirst = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
            cert,
            t,
            signatureId: "same-id");

        var sigSecond = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
            cert,
            t,
            signatureId: "same-id");

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
        edoc.AddSignature(sigFirst);
        edoc.AddSignature(sigSecond);

        Assert.True(edoc.TryResolveSignature("same-id", out var resolved));
        Assert.Same(edoc.GetSignatureAt(0), resolved);
        Assert.NotSame(edoc.GetSignatureAt(1), resolved);
    }
}
