using System.Security.Cryptography.X509Certificates;
using eDocLib;
using eDocLib.Validation;
using eDocLib.Validation.Reporting;
using Xunit;

namespace eDocLib.Tests;

/// <summary>EP-13: pre-built synthetic LT container + <see cref="EdocValidation.OpenAndValidate"/>.</summary>
public class LtFixtureOpenAndValidateTests
{
    private static string FixturePath(string name) =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "lt", name);

    [Fact]
    public void OpenAndValidate_synthetic_lt_fixture_succeeds_with_bundled_anchor()
    {
        var edocPath = FixturePath("synthetic-ocsp-lt.edoc");
        var anchorPath = FixturePath("synthetic-ocsp-lt-anchor.cer");
        Assert.True(File.Exists(edocPath), "Missing fixture: run tools/LtFixtureGen");
        Assert.True(File.Exists(anchorPath), "Missing anchor: run tools/LtFixtureGen");

        using var issuer = new X509Certificate2(anchorPath);
        using var fs = File.OpenRead(edocPath);
        var policy = new SignatureTrustPolicy
        {
            ValidateCertificateChain = true,
            RevocationMode = X509RevocationMode.NoCheck,
            CustomTrustAnchors = new X509Certificate2Collection(issuer),
            VerifyUnsignedRevocationWhenPresent = true,
            StrictEmbeddedOcspValidateResponderCertificateChain = true,
        };

        var read = EdocValidation.OpenAndValidate(fs, policy);
        Assert.True(read.AllSignaturesValid, read.Signatures.ElementAtOrDefault(0)?.Result.Error);
        Assert.True(read.Signatures[0].Result.Success);
        Assert.True(read.Signatures[0].Result.UnsignedRevocationArtifactsValid);
    }

    [Fact]
    public void BuildValidationReport_synthetic_lt_fixture_shows_qualified_profile_and_revocation_passed()
    {
        var edocPath = FixturePath("synthetic-ocsp-lt.edoc");
        var anchorPath = FixturePath("synthetic-ocsp-lt-anchor.cer");
        Assert.True(File.Exists(edocPath));
        Assert.True(File.Exists(anchorPath));

        using var issuer = new X509Certificate2(anchorPath);
        using var fs = File.OpenRead(edocPath);
        var policy = new SignatureTrustPolicy
        {
            ValidateCertificateChain = true,
            RevocationMode = X509RevocationMode.NoCheck,
            CustomTrustAnchors = new X509Certificate2Collection(issuer),
            VerifyUnsignedRevocationWhenPresent = true,
            StrictEmbeddedOcspValidateResponderCertificateChain = true,
        };

        var read = EdocValidation.OpenAndValidate(fs, policy);
        Assert.True(read.AllSignaturesValid);

        var report = read.BuildValidationReport(policy);
        Assert.True(report.AllSignaturesValid);
        var sigReport = Assert.Single(report.Signatures);
        Assert.Equal(SignatureProfile.QualifiedSignature, sigReport.SignatureProfile);
        Assert.Equal(SignatureValidationIndication.TotalPassed, sigReport.Indication);

        var rev = Assert.Single(sigReport.Tree.Children, n => n.Type == ValidationType.SignatureRevocation);
        Assert.Equal(ValidationStatus.Passed, rev.Status);
        Assert.Contains(rev.Children, c => c.Type == ValidationType.SignatureRevocationEmbeddedUnsigned && c.Status == ValidationStatus.Passed);
    }
}
