using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib;
using eDocLib.Asic.Container;
using eDocLib.Validation;
using eDocLib.Validation.Reporting;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

public class EdocArchiveSigningJobTests
{
    [Fact]
    public async Task AppendArchiveTimeStampAsync_default_imprint_then_validate_edoc_round_trip()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=lta-job", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "lta-payload"u8.ToArray();
        using var edoc = Edoc.CreateNew();
        edoc.AddDataObject(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");

        var sig = XadesBesSigner.Sign(
            edoc.DataFiles,
            cert,
            DateTimeOffset.Parse("2026-03-01T12:00:00Z"));
        edoc.AddSignature(sig);

        var tsp = new LocalSha256Rfc3161TimestampProvider();
        var job = new EdocArchiveSigningJob(edoc);
        await job.AppendArchiveTimeStampAsync(0, tsp);

        using var zip = new MemoryStream();
        edoc.Save(zip);
        zip.Position = 0;

        var policy = new SignatureTrustPolicy
        {
            ValidateArchiveTimeStampCms = true,
            ValidateArchiveTimeStampChain = true,
            CustomTrustAnchors = new X509Certificate2Collection(LocalSha256Rfc3161TimestampProvider.EmbeddedTsaCertificate),
        };

        var report = EdocValidation.OpenAndValidate(zip, policy);
        Assert.True(report.AllSignaturesValid, report.Signatures[0].Result.Error);
        Assert.Equal(1, report.Signatures[0].Result.ArchiveTimeStampCount);
        Assert.True(report.Signatures[0].Result.ArchiveTimeStampsCmsValid);
        Assert.True(report.Signatures[0].Result.ArchiveTimeStampImprintsValid);

        var xs = Assert.IsType<AsicSignature>(edoc.GetSignatureAt(0));
        Assert.Equal(SignatureProfile.ArchivedSignature, ValidationReportQualifications.EstimateSignatureProfile(xs));
    }

    [Fact]
    public async Task AppendArchiveTimeStampAsync_twice_yields_two_tokens_distinct_ids()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=lta-chain", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        using var edoc = Edoc.CreateNew();
        edoc.AddDataObject(new MemoryStream("x"u8.ToArray()), "doc.txt", "text/plain");
        edoc.AddSignature(
            XadesBesSigner.Sign(edoc.DataFiles, cert, DateTimeOffset.Parse("2026-04-01T00:00:00Z")));

        var tsp = new LocalSha256Rfc3161TimestampProvider();
        var job = new EdocArchiveSigningJob(edoc);
        await job.AppendArchiveTimeStampAsync(0, tsp);
        await job.AppendArchiveTimeStampAsync(0, tsp);

        var asic = Assert.IsType<AsicSignature>(edoc.GetSignatureAt(0));
        Assert.Equal(2, asic.UnsignedEncapsulatedArchiveTimeStampDer.Count);

        using var zip = new MemoryStream();
        edoc.Save(zip);
        zip.Position = 0;

        var policy = new SignatureTrustPolicy
        {
            ValidateArchiveTimeStampCms = true,
            ValidateArchiveTimeStampChain = true,
            CustomTrustAnchors = new X509Certificate2Collection(LocalSha256Rfc3161TimestampProvider.EmbeddedTsaCertificate),
        };

        var report = EdocValidation.OpenAndValidate(zip, policy);
        Assert.True(report.AllSignaturesValid, report.Signatures[0].Result.Error);
        Assert.Equal(2, report.Signatures[0].Result.ArchiveTimeStampCount);
        Assert.True(report.Signatures[0].Result.ArchiveTimeStampImprintsValid);
    }
}
