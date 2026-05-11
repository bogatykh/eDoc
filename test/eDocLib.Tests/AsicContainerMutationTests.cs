using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib;
using eDocLib.Validation;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

/// <summary>Removing payload files / signatures from <see cref="Asic.AsicContainer"/> via <see cref="Edoc"/>.</summary>
public class AsicContainerMutationTests
{
    [Fact]
    public async Task RemoveDataFileAt_first_entry_shifts_remaining_names()
    {
        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream("a"u8.ToArray()), "first.txt", "text/plain");
        edoc.AddDataFile(new MemoryStream("b"u8.ToArray()), "second.txt", "text/plain");

        edoc.RemoveDataFileAt(0);

        Assert.Single(edoc.DataFiles);
        Assert.Equal("second.txt", edoc.GetDataFileAt(0).Name);
    }

    [Fact]
    public async Task RemoveSignatureAt_removes_by_index_order()
    {
        using var rsa1 = RSA.Create(2048);
        using var rsa2 = RSA.Create(2048);
        var req1 = new CertificateRequest("CN=s1", rsa1, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var req2 = new CertificateRequest("CN=s2", rsa2, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert1 = req1.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        using var cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "shared"u8.ToArray();
        var t = DateTimeOffset.Parse("2026-12-12T12:00:00Z");

        var sig1 = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
            cert1,
            t,
            signatureId: "sig-1");
        var sig2 = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
            cert2,
            t,
            signatureId: "sig-2");

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
        edoc.AddSignature(sig1);
        edoc.AddSignature(sig2);

        edoc.RemoveSignatureAt(0);
        Assert.Single(edoc.Signatures);
        Assert.Equal("sig-2", edoc.GetSignatureAt(0).Id);

        using var zip = new MemoryStream();
        edoc.Save(zip);
        zip.Position = 0;

        var report = await EdocValidation.OpenAndValidateAsync(zip, SignatureTrustPolicy.CryptographyOnly);
        Assert.True(report.AllSignaturesValid);
    }
}
