using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib;
using eDocLib.Validation;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

/// <summary>Edge inputs for <see cref="XadesBesSigner"/> / detached verification.</summary>
public class XadesBesSignerEdgeCaseTests
{
    [Fact]
    public void Sign_no_data_files_detached_verifier_accepts_empty_payload_map()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=no-files", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var sig = XadesBesSigner.Sign(
            Array.Empty<DataFile>(),
            cert,
            DateTimeOffset.Parse("2026-12-01T10:00:00Z"),
            signatureId: "sig-empty-inputs");

        Assert.True(
            DetachedSignatureVerifier.TryVerify(sig, new Dictionary<string, byte[]>(), out var err),
            err);
    }

    [Fact]
    public void Empty_container_with_signature_only_round_trips_and_validates()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=no-data-files-container", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var sig = XadesBesSigner.Sign(
            Array.Empty<DataFile>(),
            cert,
            DateTimeOffset.Parse("2026-12-02T11:00:00Z"));

        var edoc = Edoc.CreateNew();
        edoc.AddSignature(sig);

        using var zip = new MemoryStream();
        edoc.Save(zip);
        zip.Position = 0;

        var report = EdocValidation.OpenAndValidate(zip, SignatureTrustPolicy.CryptographyOnly);
        Assert.True(report.AllSignaturesValid, report.Signatures.ElementAtOrDefault(0)?.Result.Error);
        Assert.Empty(report.Edoc.DataFiles);
    }
}
