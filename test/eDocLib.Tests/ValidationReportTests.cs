using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib;
using eDocLib.Validation;
using eDocLib.Validation.Reporting;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

public class ValidationReportTests
{
    [Fact]
    public async Task BuildValidationReport_Bes_signature_has_tree_and_revocation_snapshot()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=report-bes", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "hello"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "a.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2025-06-01T00:00:00Z"));

        using var ms = new MemoryStream();
        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "a.txt", "text/plain");
        edoc.AddSignature(sig);
        edoc.Save(ms);
        ms.Position = 0;

        var policy = SignatureTrustPolicy.CryptographyOnly;
        var read = await EdocValidation.OpenAndValidateAsync(ms, policy);
        Assert.True(read.AllSignaturesValid);

        var report = read.BuildValidationReport(policy);
        Assert.True(report.AllSignaturesValid);
        Assert.Equal(ValidationStatus.Passed, report.Root.Status);
        Assert.Single(report.Signatures);
        var s = report.Signatures[0];
        Assert.Equal(ValidationSignatureType.EdocV2, s.ValidationSignatureType);
        Assert.Equal(SignatureProfile.BasicSignature, s.SignatureProfile);
        Assert.Equal(SignatureValidationIndication.TotalPassed, s.Indication);
        Assert.NotNull(s.RawResult.Revocation);
        var rev = s.RawResult.Revocation!;
        Assert.Null(rev.EffectiveChainRevocationMode);
        Assert.False(rev.HasEmbeddedRevocationArtifacts);
        Assert.False(rev.HasNonEmptyOnlineFetchedRevocation);
        Assert.False(rev.ApplicationOnlineFetchSkippedForSelfSignedShortChain);

        Assert.Equal(ValidationType.Root, report.Root.Type);
        Assert.Contains(
            report.Root.Children,
            c => c.Type == ValidationType.Structure && c.Status == ValidationStatus.Passed);
        Assert.Equal(ValidationType.Signature, s.Tree.Type);
        Assert.Contains(
            s.Tree.Children,
            n => n.Type == ValidationType.SignatureEdocDataObjectReferences && n.Status == ValidationStatus.Passed);

        var revBranch = Assert.Single(s.Tree.Children, n => n.Type == ValidationType.SignatureRevocation);
        Assert.Equal(ValidationStatus.Unchecked, revBranch.Status);
        Assert.Equal(3, revBranch.Children.Count);
        Assert.Contains(revBranch.Children, n => n.Type == ValidationType.SignatureRevocationPkixChainMode);
        Assert.Contains(revBranch.Children, n => n.Type == ValidationType.SignatureRevocationEmbeddedUnsigned);
        Assert.Contains(revBranch.Children, n => n.Type == ValidationType.SignatureRevocationApplicationOnline);
    }

    [Fact]
    public async Task ValidationReportTextFormatter_includes_tree_and_summary()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=report-text", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "x"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "f.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2025-06-01T00:00:00Z"));
        using var ms = new MemoryStream();
        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "f.txt", "text/plain");
        edoc.AddSignature(sig);
        edoc.Save(ms);
        ms.Position = 0;

        var policy = SignatureTrustPolicy.CryptographyOnly;
        var read = await EdocValidation.OpenAndValidateAsync(ms, policy);
        var report = read.BuildValidationReport(policy);
        var text = report.ToPlainText(new DefaultValidationReportLocalizer());
        Assert.Contains("Document: all signatures valid", text);
        Assert.Contains("Root", text);
        Assert.Contains("Signature count", text);
        Assert.Contains("EDOC v2", text);
    }

    [Fact]
    public async Task ResourceValidationReportLocalizer_reads_embedded_resx()
    {
        var loc = ResourceValidationReportLocalizer.ForEmbeddedDefaults();
        Assert.Equal("All checks passed", loc.Indication(SignatureValidationIndication.TotalPassed));
        Assert.Equal("OK", loc.DescribeValidationStatus(ValidationStatus.Passed));
    }

    [Fact]
    public async Task ResourceValidationReportLocalizer_resx_defines_keys_for_all_reporting_enums()
    {
        var res = ResourceValidationReportLocalizer.ForEmbeddedDefaults(CultureInfo.InvariantCulture);
        var def = new DefaultValidationReportLocalizer(CultureInfo.InvariantCulture);

        foreach (ValidationType t in Enum.GetValues<ValidationType>())
        {
            Assert.False(string.IsNullOrWhiteSpace(res.ValidationTypeCaption(t)));
        }

        foreach (ValidationStatus s in Enum.GetValues<ValidationStatus>())
        {
            Assert.False(string.IsNullOrWhiteSpace(res.DescribeValidationStatus(s)));
        }

        foreach (SignatureProfile p in Enum.GetValues<SignatureProfile>())
        {
            Assert.Equal(def.DescribeSignatureProfile(p), res.DescribeSignatureProfile(p));
        }

        foreach (SignatureQualification q in Enum.GetValues<SignatureQualification>())
        {
            Assert.Equal(def.DescribeSignatureQualification(q), res.DescribeSignatureQualification(q));
        }

        foreach (CertificateQualification q in Enum.GetValues<CertificateQualification>())
        {
            Assert.Equal(def.DescribeCertificateQualification(q), res.DescribeCertificateQualification(q));
        }

        foreach (TimestampQualification q in Enum.GetValues<TimestampQualification>())
        {
            Assert.Equal(def.DescribeTimestampQualification(q), res.DescribeTimestampQualification(q));
        }

        foreach (ValidationSignatureType t in Enum.GetValues<ValidationSignatureType>())
        {
            Assert.Equal(def.DescribeValidationSignatureType(t), res.DescribeValidationSignatureType(t));
        }

        Assert.Equal("All checks passed", res.Indication(SignatureValidationIndication.TotalPassed));
        Assert.Equal(def.Indication(SignatureValidationIndication.TotalFailed), res.Indication(SignatureValidationIndication.TotalFailed));
        Assert.Equal(def.LegalBasisHint(SignatureValidationIndication.Indeterminate), res.LegalBasisHint(SignatureValidationIndication.Indeterminate));
    }

    [Fact]
    public async Task BuildValidationReport_chain_includes_serial_and_validity_nodes()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=chain-nodes", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "c"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "a.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2025-06-01T00:00:00Z"));
        using var ms = new MemoryStream();
        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "a.txt", "text/plain");
        edoc.AddSignature(sig);
        edoc.Save(ms);
        ms.Position = 0;

        var policy = new SignatureTrustPolicy
        {
            ValidateCertificateChain = true,
            RevocationMode = X509RevocationMode.NoCheck,
            CustomTrustAnchors = new X509Certificate2Collection(cert),
        };
        var read = await EdocValidation.OpenAndValidateAsync(ms, policy);
        var report = read.BuildValidationReport(policy);
        var paths = report.Signatures[0].CertificatePaths;
        Assert.NotNull(paths.SigningCertificatePath);
        Assert.Single(paths.SigningCertificatePath!);
        Assert.True(paths.SigningPathFullyTrusted);
        Assert.Null(paths.TimeStampAuthorityPath);
        Assert.Null(paths.TimeStampAuthorityPathFullyTrusted);

        var chain = report.Signatures[0].Tree.Children.First(n => n.Type == ValidationType.SignatureSigningCertificateChain);
        Assert.NotEmpty(chain.Children);
        var firstCert = chain.Children[0];
        Assert.Equal(ValidationType.SignatureSigningCertificate, firstCert.Type);
        Assert.StartsWith("End entity:", firstCert.Description ?? "", StringComparison.Ordinal);
        Assert.Contains(
            firstCert.Children,
            c => c.Type == ValidationType.SignatureSigningCertificateSerial && c.Status == ValidationStatus.Passed);
        var validity = Assert.Single(firstCert.Children, c => c.Type == ValidationType.SignatureSigningCertificateValidity);
        Assert.Equal(ValidationStatus.Passed, validity.Status);
        Assert.Contains(validity.Children, n => n.Type == ValidationType.SignatureSigningCertificateNotBefore);
        Assert.Contains(validity.Children, n => n.Type == ValidationType.SignatureSigningCertificateNotAfter);
    }

    [Fact]
    public async Task BuildValidationReport_chain_labels_end_entity_intermediate_and_trust_anchor()
    {
        using var rootRsa = RSA.Create(2048);
        var rootReq = new CertificateRequest("CN=Root", rootRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, false));
        rootReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootReq.PublicKey, false));
        using var root = rootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddYears(10));

        using var subRsa = RSA.Create(2048);
        var subReq = new CertificateRequest("CN=Sub CA", subRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        subReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        subReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, false));
        subReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(subReq.PublicKey, false));
        var subSerial = new byte[8];
        RandomNumberGenerator.Fill(subSerial);
        using var subPub = subReq.Create(root, DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddYears(5), subSerial);
        using var sub = subPub.CopyWithPrivateKey(subRsa);

        using var leafRsa = RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=Leaf", leafRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        var leafSerial = new byte[8];
        RandomNumberGenerator.Fill(leafSerial);
        using var leafPub = leafReq.Create(sub, DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddYears(1), leafSerial);
        using var leaf = leafPub.CopyWithPrivateKey(leafRsa);

        var payload = "chain-labels"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "a.txt", "text/plain") },
            leaf,
            DateTimeOffset.Parse("2025-06-01T00:00:00Z"));
        using var ms = new MemoryStream();
        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "a.txt", "text/plain");
        edoc.AddSignature(sig);
        edoc.Save(ms);
        ms.Position = 0;

        var policy = new SignatureTrustPolicy
        {
            ValidateCertificateChain = true,
            RevocationMode = X509RevocationMode.NoCheck,
            CustomTrustAnchors = new X509Certificate2Collection(root),
            ExtraChainCertificates = new X509Certificate2Collection(sub),
        };
        var read = await EdocValidation.OpenAndValidateAsync(ms, policy);
        Assert.True(read.AllSignaturesValid, read.Signatures[0].Result.Error);
        var report = read.BuildValidationReport(policy);
        var pathSummary = report.Signatures[0].CertificatePaths;
        Assert.NotNull(pathSummary.SigningCertificatePath);
        Assert.Equal(3, pathSummary.SigningCertificatePath!.Count);
        Assert.True(pathSummary.SigningPathFullyTrusted);

        var chainBranch = report.Signatures[0].Tree.Children.First(n => n.Type == ValidationType.SignatureSigningCertificateChain);
        Assert.Equal(3, chainBranch.Children.Count);
        Assert.StartsWith("End entity:", chainBranch.Children[0].Description ?? "", StringComparison.Ordinal);
        Assert.StartsWith("Intermediate:", chainBranch.Children[1].Description ?? "", StringComparison.Ordinal);
        Assert.StartsWith("Trust anchor:", chainBranch.Children[2].Description ?? "", StringComparison.Ordinal);
    }

    [Fact]
    public async Task BuildValidationReport_ReferenceTimeUtc_marks_not_after_failed_when_reference_after_cert_validity()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=ref-time", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "t"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "a.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2025-06-01T00:00:00Z"));
        using var ms = new MemoryStream();
        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "a.txt", "text/plain");
        edoc.AddSignature(sig);
        edoc.Save(ms);
        ms.Position = 0;

        var policy = new SignatureTrustPolicy
        {
            ValidateCertificateChain = true,
            RevocationMode = X509RevocationMode.NoCheck,
            CustomTrustAnchors = new X509Certificate2Collection(cert),
        };
        var read = await EdocValidation.OpenAndValidateAsync(ms, policy);
        Assert.True(read.AllSignaturesValid, read.Signatures[0].Result.Error);

        var refLate = DateTimeOffset.UtcNow.AddYears(10);
        var report = read.BuildValidationReport(
            policy,
            new ValidationReportOptions { ReferenceTimeUtc = refLate });

        var chainBranch = report.Signatures[0].Tree.Children.First(n => n.Type == ValidationType.SignatureSigningCertificateChain);
        var firstCert = chainBranch.Children[0];
        var validity = Assert.Single(firstCert.Children, c => c.Type == ValidationType.SignatureSigningCertificateValidity);
        var notAfter = Assert.Single(validity.Children, c => c.Type == ValidationType.SignatureSigningCertificateNotAfter);
        Assert.Equal(ValidationStatus.Failed, notAfter.Status);
    }

    [Fact]
    public async Task BuildValidationReport_includes_signer_roles_and_production_place_nodes()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=x09-report", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "x09-report"u8.ToArray();
        var place = new SignatureProductionPlace(City: "Riga", CountryName: "LV");
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2025-08-01T00:00:00Z"),
            signerRoles: new[] { "Author" },
            productionPlace: place);

        using var ms = new MemoryStream();
        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
        edoc.AddSignature(sig);
        edoc.Save(ms);
        ms.Position = 0;

        var policy = new SignatureTrustPolicy
        {
            ValidateCertificateChain = true,
            RevocationMode = X509RevocationMode.NoCheck,
            CustomTrustAnchors = new X509Certificate2Collection(cert),
            RequireAtLeastOneSignerClaimedRole = true,
        };

        var read = await EdocValidation.OpenAndValidateAsync(ms, policy);
        Assert.True(read.AllSignaturesValid, read.Signatures[0].Result.Error);
        Assert.True(read.Signatures[0].Result.SignerClaimedRolesConstraintOk);

        var report = read.BuildValidationReport(policy);
        var tree = report.Signatures[0].Tree;
        var rolesNode = Assert.Single(tree.Children, n => n.Type == ValidationType.SignatureSignerClaimedRoles);
        Assert.Equal(ValidationStatus.Passed, rolesNode.Status);
        Assert.Contains("Author", rolesNode.Description ?? "", StringComparison.Ordinal);

        var placeNode = Assert.Single(tree.Children, n => n.Type == ValidationType.SignatureProductionPlace);
        Assert.Equal(ValidationStatus.Passed, placeNode.Status);
        Assert.Contains("Riga", placeNode.Description ?? "", StringComparison.Ordinal);
    }

    [Fact]
    public async Task DictionaryValidationReportLocalizer_overrides_enum_captions()
    {
        var dict = new Dictionary<string, string>
        {
            [$"{nameof(SignatureValidationIndication)}.{nameof(SignatureValidationIndication.TotalPassed)}"] = "OK",
            [$"{nameof(ValidationStatus)}.{nameof(ValidationStatus.Passed)}"] = "Fine",
        };
        var loc = new DictionaryValidationReportLocalizer(dict);
        Assert.Equal("OK", loc.Indication(SignatureValidationIndication.TotalPassed));
        Assert.Equal("Fine", loc.DescribeValidationStatus(ValidationStatus.Passed));
        Assert.Equal("Total failed", loc.Indication(SignatureValidationIndication.TotalFailed));
    }
}
