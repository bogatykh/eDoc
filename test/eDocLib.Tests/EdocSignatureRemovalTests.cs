using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

/// <summary><see cref="Asic.AsicContainer.RemoveSignature"/> / <see cref="Asic.AsicContainer.RemoveSignatureAt"/> behaviour on <see cref="Edoc"/>.</summary>
public class EdocSignatureRemovalTests
{
    [Fact]
    public void RemoveSignature_nonexistent_id_returns_false_without_side_effects()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=rm-sig", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "x"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2026-01-10T12:00:00Z"),
            signatureId: "present");

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
        edoc.AddSignature(sig);

        Assert.False(edoc.RemoveSignature("missing-id"));
        Assert.Single(edoc.Signatures);
    }

    [Fact]
    public void Remove_existing_signature_then_save_load_yields_no_signatures()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=drop-sig", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "z"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "only.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2026-12-04T13:00:00Z"),
            signatureId: "removable");

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "only.txt", "text/plain");
        edoc.AddSignature(sig);

        Assert.True(edoc.RemoveSignature("removable"));
        Assert.Empty(edoc.Signatures);

        using var zip = new MemoryStream();
        edoc.Save(zip);
        zip.Position = 0;

        var loaded = new Edoc(zip);
        Assert.Empty(loaded.Signatures);
        Assert.Single(loaded.DataFiles);
    }
}
