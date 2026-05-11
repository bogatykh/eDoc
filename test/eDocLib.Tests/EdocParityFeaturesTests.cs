using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using eDocLib;
using eDocLib.Asic.Container;
using eDocLib.Validation;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

public class EdocParityFeaturesTests
{
    [Fact]
    public void AsicContainerFormatProbe_detects_round_trip_edoc()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=probe", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "x"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload), "a.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2024-01-01T00:00:00Z"),
            signatureId: "S-custom");

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload), "a.txt", "text/plain");
        edoc.AddSignature(sig);

        using var ms = new MemoryStream();
        edoc.Save(ms);
        ms.Position = 0;

        Assert.True(AsicContainerFormatProbe.TryDetectAsicE(ms, out var probe), probe.RejectionReason);
        Assert.True(probe.IsLikelyAsicE);
        Assert.True(probe.MimeTypeEntryValid);
        Assert.True(probe.ManifestEntrySeen);
        Assert.Equal(0, ms.Position);
    }

    [Fact]
    public void AsicContainerFormatProbe_rejects_wrong_first_entry()
    {
        using var ms = new MemoryStream();
        using (var zip = new ICSharpCode.SharpZipLib.Zip.ZipOutputStream(ms) { IsStreamOwner = false })
        {
            zip.PutNextEntry(new ICSharpCode.SharpZipLib.Zip.ZipEntry("wrong.txt")
            {
                CompressionMethod = ICSharpCode.SharpZipLib.Zip.CompressionMethod.Stored,
            });
            var bytes = Encoding.UTF8.GetBytes("hello");
            zip.Write(bytes, 0, bytes.Length);
            zip.CloseEntry();
        }

        ms.Position = 0;
        Assert.False(AsicContainerFormatProbe.TryDetectAsicE(ms, out var probe));
        Assert.False(probe.MimeTypeEntryValid);
        Assert.NotNull(probe.RejectionReason);
    }

    [Fact]
    public void TryResolveSignature_and_TryGetSignature_resolve_by_xml_id()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=id", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "y"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload), "b.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2024-02-02T00:00:00Z"),
            signatureId: "sig-42");

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload), "b.txt", "text/plain");
        edoc.AddSignature(sig);

        Assert.True(edoc.TryResolveSignature("sig-42", out var raw));
        Assert.Same(sig, raw);
        Assert.True(edoc.TryGetSignature("sig-42", out var info));
        Assert.NotNull(info);
        Assert.Equal("sig-42", info!.Id);
        Assert.False(edoc.TryResolveSignature("missing", out _));
        Assert.False(edoc.TryGetSignature("missing", out _));
    }

    [Fact]
    public void SignatureProductionPlace_round_trips()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=place", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var place = new SignatureProductionPlace(City: "Riga", CountryName: "LV");
        var payload = "z"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload), "c.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2024-03-03T00:00:00Z"),
            productionPlace: place);

        Assert.NotNull(sig.SignatureProductionPlace);
        Assert.Equal("Riga", sig.SignatureProductionPlace!.City);
        Assert.Equal("LV", sig.SignatureProductionPlace.CountryName);

        using var zip = new MemoryStream();
        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload), "c.txt", "text/plain");
        edoc.AddSignature(sig);
        edoc.Save(zip);
        zip.Position = 0;

        var loaded = new Edoc(zip);
        var round = Assert.IsType<AsicSignature>(Assert.Single(loaded.Signatures));
        Assert.NotNull(round.SignatureProductionPlace);
        Assert.Equal("Riga", round.SignatureProductionPlace!.City);
        Assert.Equal("LV", round.SignatureProductionPlace.CountryName);
    }

    [Fact]
    public async Task IValidatableDocument_Validate_delegates_to_EdocValidation()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=val", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "q"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload), "d.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2024-04-04T00:00:00Z"));

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload), "d.txt", "text/plain");
        edoc.AddSignature(sig);
        IValidatableDocument validatable = edoc;

        var report = await validatable.ValidateAsync(SignatureTrustPolicy.CryptographyOnly);
        Assert.True(report.AllSignaturesValid);
    }
}
