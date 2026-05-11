using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib;
using eDocLib.Validation;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

/// <summary>Calling <see cref="EdocValidation.ValidateSignaturesAsync"/> repeatedly on the same <see cref="Edoc"/> instance.</summary>
public class EdocValidationRepeatabilityTests
{
    [Fact]
    public async Task ValidateSignatures_can_run_twice_on_same_edoc_instance()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=twice-validate", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "twice-check"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2026-12-07T16:00:00Z"));

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
        edoc.AddSignature(sig);

        var r1 = await EdocValidation.ValidateSignaturesAsync(edoc, SignatureTrustPolicy.CryptographyOnly);
        var r2 = await EdocValidation.ValidateSignaturesAsync(edoc, SignatureTrustPolicy.CryptographyOnly);

        Assert.True(r1.AllSignaturesValid, r1.Signatures.ElementAtOrDefault(0)?.Result.Error);
        Assert.True(r2.AllSignaturesValid, r2.Signatures.ElementAtOrDefault(0)?.Result.Error);
    }
}
