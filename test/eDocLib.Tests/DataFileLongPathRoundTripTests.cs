using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib;
using eDocLib.Validation;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

/// <summary>Very long relative paths as <see cref="IDataFile.Name"/> inside ASiC-E.</summary>
public class DataFileLongPathRoundTripTests
{
    [Fact]
    public void Long_single_segment_name_round_trips_and_validates()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=long-name", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var relativeName = new string('s', 160) + ".bin";
        Assert.Equal(164, relativeName.Length);

        var payload = "long-path-payload"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), relativeName, "application/octet-stream") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2026-12-17T14:00:00Z"));

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
