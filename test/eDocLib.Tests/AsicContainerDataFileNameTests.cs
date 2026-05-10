using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib;
using eDocLib.Validation;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

/// <summary>ZIP entry paths / <see cref="IDataFile.Name"/> behaviour on round-trip through <see cref="Asic.AsicContainer"/>.</summary>
public class AsicContainerDataFileNameTests
{
    [Fact]
    public void Zip_entry_name_with_dot_segments_round_trips_literal_string()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=dots", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var relativeName = "vault/../literal-name.bin";
        var payload = "dot-seg"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), relativeName, "application/octet-stream") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2026-12-05T14:00:00Z"));

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), relativeName, "application/octet-stream");
        edoc.AddSignature(sig);

        using var zip = new MemoryStream();
        edoc.Save(zip);
        zip.Position = 0;

        var loaded = new Edoc(zip);
        Assert.Single(loaded.DataFiles);
        Assert.Equal(relativeName, loaded.DataFiles.First().Name);

        var report = EdocValidation.ValidateSignatures(loaded, SignatureTrustPolicy.CryptographyOnly);
        Assert.True(report.AllSignaturesValid, report.Signatures.ElementAtOrDefault(0)?.Result.Error);
    }
}
