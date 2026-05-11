using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using eDocLib.Asic.Container;
using eDocLib.Timestamp;
using eDocLib.Validation;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib;

public class XadesTAndSignerRolesTests
{
    [Fact]
    public async Task X09_signer_roles_emitted_and_round_tripped_on_signature()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=role-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var dfs = new[] { new DataFile(new MemoryStream("r"u8.ToArray()), "doc.txt", "text/plain") };
        var roles = new[] { "Author", "Reviewer" };

        var sig = XadesBesSigner.Sign(
            dfs,
            cert,
            DateTimeOffset.Parse("2024-03-01T12:00:00Z"),
            signerRoles: roles);

        Assert.Equal(roles, sig.SignerRoles);

        using var ms = new MemoryStream();
        sig.WriteTo(ms);
        var doc = new XmlDocument { PreserveWhitespace = false };
        doc.LoadXml(Encoding.UTF8.GetString(ms.ToArray()));

        var nsm = new XmlNamespaceManager(doc.NameTable);
        nsm.AddNamespace("xades", XadesSignature.XadesNamespaceUrl);
        var nodes = doc.SelectNodes("//xades:ClaimedRole", nsm);
        Assert.NotNull(nodes);
        Assert.Equal(2, nodes!.Count);
        var parsed = new List<string>();
        foreach (XmlNode n in nodes)
        {
            parsed.Add(n!.InnerText.Trim());
        }

        Assert.Equal(roles, parsed);
    }

    [Fact]
    public async Task X09_claimed_role_policy_require_one_fails_when_missing()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=role-pol", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "p"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2024-03-01T12:00:00Z"));

        var policy = new SignatureTrustPolicy { RequireAtLeastOneSignerClaimedRole = true };
        var r = await SignatureValidator.ValidateAsync(sig, new Dictionary<string, byte[]> { ["doc.txt"] = payload }, policy);
        Assert.False(r.Success);
        Assert.Contains("ClaimedRole", r.Error ?? "", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task X09_claimed_role_allow_list_rejects_unknown_role()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=role-allow", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "p"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2024-03-01T12:00:00Z"),
            signerRoles: new[] { "Author" });

        var policy = new SignatureTrustPolicy { SignerClaimedRoleAllowList = new[] { "Reviewer" } };
        var r = await SignatureValidator.ValidateAsync(sig, new Dictionary<string, byte[]> { ["doc.txt"] = payload }, policy);
        Assert.False(r.Success);
        Assert.Contains("Author", r.Error ?? "", StringComparison.Ordinal);
    }

    [Fact]
    public async Task X09_claimed_role_allow_list_accepts_listed_role()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=role-ok", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "p"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2024-03-01T12:00:00Z"),
            signerRoles: new[] { "Author" });

        var policy = new SignatureTrustPolicy { SignerClaimedRoleAllowList = new[] { "Author", "Reviewer" } };
        var r = await SignatureValidator.ValidateAsync(sig, new Dictionary<string, byte[]> { ["doc.txt"] = payload }, policy);
        Assert.True(r.Success, r.Error);
    }

    [Fact]
    public async Task X07_sign_with_timestamp_embeds_token_and_validates_container()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=ts-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "timestamped"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var tsp = new LocalSha256Rfc3161TimestampProvider();

        var sig = await XadesBesSigner.SignWithTimestampAsync(
            dfs,
            cert,
            DateTimeOffset.Parse("2024-04-01T09:00:00Z"),
            tsp,
            signerRoles: new[] { "Signer" });

        Assert.Single(sig.SignerRoles);
        Assert.Equal("Signer", sig.SignerRoles.First());

        var owner = sig.GetSignatureOwnerDocument();
        var encList = owner.GetElementsByTagName("EncapsulatedTimeStamp", XadesSignature.XadesNamespaceUrl);
        Assert.True(encList.Count > 0);

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
        edoc.AddSignature(sig);

        using var zip = new MemoryStream();
        edoc.Save(zip);
        zip.Position = 0;

        var report = await EdocValidation.OpenAndValidateAsync(zip, SignatureTrustPolicy.CryptographyOnly);
        Assert.True(report.AllSignaturesValid);
    }

    [Fact]
    public async Task SignatureTimestamp_imprint_verifier_succeeds_for_sign_with_timestamp()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=tsv", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var dfs = new[] { new DataFile(new MemoryStream("v"u8.ToArray()), "doc.txt", "text/plain") };
        var tsp = new LocalSha256Rfc3161TimestampProvider();

        var sig = await XadesBesSigner.SignWithTimestampAsync(
            dfs,
            cert,
            DateTimeOffset.Parse("2024-05-01T00:00:00Z"),
            tsp);

        var ok = SignatureTimestampVerifier.TryVerifySignatureTimeStampImprint(sig.GetSignatureOwnerDocument(), out var err);
        Assert.True(ok, err);
    }

    [Fact]
    public async Task SignatureTimestamp_imprint_verifier_fails_on_garbage_encapsulated_token()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=bad-ts", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var dfs = new[] { new DataFile(new MemoryStream("x"u8.ToArray()), "doc.txt", "text/plain") };
        var bad = new PrecomputedTimestampTokenProvider(new byte[] { 1, 2, 3, 4, 5 });

        var sig = await XadesBesSigner.SignWithTimestampAsync(
            dfs,
            cert,
            DateTimeOffset.Parse("2024-05-02T00:00:00Z"),
            bad);

        var ok = SignatureTimestampVerifier.TryVerifySignatureTimeStampImprint(sig.GetSignatureOwnerDocument(), out var err);
        Assert.False(ok);
        Assert.False(string.IsNullOrEmpty(err));
    }

    [Fact]
    public async Task EdocValidation_timestamp_imprint_policy_passes_for_valid_TST()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=ts-pol-ok", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "policy-ok"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var sig = await XadesBesSigner.SignWithTimestampAsync(
            dfs,
            cert,
            DateTimeOffset.Parse("2024-07-01T00:00:00Z"),
            new LocalSha256Rfc3161TimestampProvider());

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
        edoc.AddSignature(sig);

        using var zip = new MemoryStream();
        edoc.Save(zip);
        zip.Position = 0;

        var report = await EdocValidation.OpenAndValidateAsync(zip, SignatureTrustPolicy.CryptographyAndTimestampImprint);
        Assert.True(report.AllSignaturesValid);
        Assert.True(report.Signatures[0].Result.SignatureTimestampImprintValid);
    }

    [Fact]
    public async Task EdocValidation_timestamp_imprint_policy_fails_for_garbage_TST()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=ts-pol-bad", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "policy-bad"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var sig = await XadesBesSigner.SignWithTimestampAsync(
            dfs,
            cert,
            DateTimeOffset.Parse("2024-07-02T00:00:00Z"),
            new PrecomputedTimestampTokenProvider(new byte[] { 9, 9, 9 }));

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
        edoc.AddSignature(sig);

        using var zip = new MemoryStream();
        edoc.Save(zip);
        zip.Position = 0;

        var report = await EdocValidation.OpenAndValidateAsync(zip, SignatureTrustPolicy.CryptographyAndTimestampImprint);
        Assert.False(report.AllSignaturesValid);
        Assert.False(report.Signatures[0].Result.SignatureTimestampImprintValid);
    }

    [Fact]
    public async Task EdocValidation_BES_with_imprint_policy_leaves_imprint_null()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=bes", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "bes"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2024-07-03T00:00:00Z"));

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
        edoc.AddSignature(sig);

        using var zip = new MemoryStream();
        edoc.Save(zip);
        zip.Position = 0;

        var report = await EdocValidation.OpenAndValidateAsync(zip, SignatureTrustPolicy.CryptographyAndTimestampImprint);
        Assert.True(report.AllSignaturesValid);
        Assert.Null(report.Signatures[0].Result.SignatureTimestampImprintValid);
    }

    [Fact]
    public async Task EdocValidation_Tsa_cms_validation_passes_for_local_tst()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=tsa-cms", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "tsa-cms"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var sig = await XadesBesSigner.SignWithTimestampAsync(
            dfs,
            cert,
            DateTimeOffset.Parse("2024-08-01T00:00:00Z"),
            new LocalSha256Rfc3161TimestampProvider());

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
        edoc.AddSignature(sig);

        using var zip = new MemoryStream();
        edoc.Save(zip);
        zip.Position = 0;

        var report = await EdocValidation.OpenAndValidateAsync(zip, SignatureTrustPolicy.CryptographyTimestampImprintAndTsaSigner);
        Assert.True(report.AllSignaturesValid, report.Signatures[0].Result.Error ?? "(no error)");
        Assert.True(report.Signatures[0].Result.SignatureTimestampImprintValid);
        Assert.True(report.Signatures[0].Result.TsaSignerCmsValid);
        Assert.Null(report.Signatures[0].Result.TsaSignerChainValid);
    }

    [Fact]
    public async Task EdocValidation_Tsa_cms_without_imprint_policy_still_validates_token()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=tsa-only", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "tsa-only"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var sig = await XadesBesSigner.SignWithTimestampAsync(
            dfs,
            cert,
            DateTimeOffset.Parse("2024-08-02T00:00:00Z"),
            new LocalSha256Rfc3161TimestampProvider());

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
        edoc.AddSignature(sig);

        using var zip = new MemoryStream();
        edoc.Save(zip);
        zip.Position = 0;

        var policy = new SignatureTrustPolicy
        {
            ValidateTsaSigner = true,
            TimestampImprintPolicy = SignatureTimestampImprintPolicy.Ignore,
        };
        var report = await EdocValidation.OpenAndValidateAsync(zip, policy);
        Assert.True(report.AllSignaturesValid);
        Assert.Null(report.Signatures[0].Result.SignatureTimestampImprintValid);
        Assert.True(report.Signatures[0].Result.TsaSignerCmsValid);
    }

    [Fact]
    public async Task EdocValidation_Tsa_chain_uses_TsaTrustAnchors()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=tsa-anchor-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "tsa-anchors"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var sig = await XadesBesSigner.SignWithTimestampAsync(
            dfs,
            cert,
            DateTimeOffset.Parse("2024-09-01T00:00:00Z"),
            new LocalSha256Rfc3161TimestampProvider());

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
        edoc.AddSignature(sig);

        using var zip = new MemoryStream();
        edoc.Save(zip);
        zip.Position = 0;

        using var tsaPublic = LocalSha256Rfc3161TimestampProvider.EmbeddedTsaCertificate;
        var policy = new SignatureTrustPolicy
        {
            TimestampImprintPolicy = SignatureTimestampImprintPolicy.RequireWhenPresent,
            ValidateTsaSigner = true,
            ValidateTsaSignerChain = true,
            TsaTrustAnchors = new X509Certificate2Collection(tsaPublic),
        };

        var report = await EdocValidation.OpenAndValidateAsync(zip, policy);
        Assert.True(report.AllSignaturesValid, report.Signatures[0].Result.Error);
        Assert.True(report.Signatures[0].Result.TsaSignerChainValid);
        Assert.NotNull(report.Signatures[0].Result.TsaSignerCertificateChain);
        Assert.NotEmpty(report.Signatures[0].Result.TsaSignerCertificateChain!);

        var docReport = report.BuildValidationReport(policy);
        var tsNode = docReport.Signatures[0].Tree.Children.First(
            n => n.Type == global::eDocLib.Validation.Reporting.ValidationType.SignatureTimestamp);
        var tsaChainBranch = Assert.Single(
            tsNode.Children,
            n => n.Type == global::eDocLib.Validation.Reporting.ValidationType.SignatureTimestampCertificateChain);
        Assert.Equal(global::eDocLib.Validation.Reporting.ValidationStatus.Passed, tsaChainBranch.Status);
        Assert.NotEmpty(tsaChainBranch.Children);
        Assert.All(
            tsaChainBranch.Children,
            c => Assert.Equal(global::eDocLib.Validation.Reporting.ValidationType.SignatureSigningCertificate, c.Type));
    }

    /// <summary>
    /// Set <c>EDOC_TEST_TSP_URL</c> to a full HTTP(S) TSP endpoint (POST, RFC 3161). Skipped when unset.
    /// </summary>
    [Fact]
    public async Task Optional_env_http_TSP_signs_and_validates_with_tsa_cms()
    {
        var url = Environment.GetEnvironmentVariable("EDOC_TEST_TSP_URL");
        if (string.IsNullOrWhiteSpace(url))
        {
            return;
        }

        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=httptsp", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "httptsp"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };

        using var tsp = new Rfc3161HttpTimestampProvider(new Uri(url.Trim()));
        var sig = await XadesBesSigner.SignWithTimestampAsync(
            dfs,
            cert,
            DateTimeOffset.Parse("2024-08-03T00:00:00Z"),
            tsp);

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
        edoc.AddSignature(sig);

        using var zip = new MemoryStream();
        edoc.Save(zip);
        zip.Position = 0;

        var report = await EdocValidation.OpenAndValidateAsync(zip, SignatureTrustPolicy.CryptographyTimestampImprintAndTsaSigner);
        Assert.True(report.AllSignaturesValid, report.Signatures[0].Result.Error);
        Assert.True(report.Signatures[0].Result.TsaSignerCmsValid);
    }
}
