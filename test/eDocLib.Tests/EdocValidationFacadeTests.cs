using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using eDocLib.Asic.Container;
using eDocLib.Asic.Xades;
using eDocLib.Configuration;
using eDocLib.Validation;
using eDocLib.Validation.Reporting;
using Xunit;

namespace eDocLib.Tests;

/// <summary>
/// Coverage for the <see cref="EdocValidation"/> facade and <see cref="EdocReadValidationResult"/>:
/// argument guards, behaviour on empty / mixed signature sets, and the deliberate "no signatures = not valid"
/// short-circuit in <see cref="EdocReadValidationResult.AllSignaturesValid"/>.
/// </summary>
public class EdocValidationFacadeTests
{
    [Fact]
    public async Task ValidateSignaturesAsync_throws_on_null_edoc()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            EdocValidation.ValidateSignaturesAsync(null!));
    }

    [Fact]
    public async Task ValidateSignaturesAsync_empty_container_returns_no_signatures_and_AllSignaturesValid_is_false()
    {
        // Security-relevant contract: an unsigned container must NOT report "all valid" merely because
        // there are zero signatures. Enumerable.All() on empty is vacuously true; the facade explicitly
        // guards against that with HasSignatures &&.
        var edoc = Edoc.CreateNew();
        var result = await EdocValidation.ValidateSignaturesAsync(edoc);

        Assert.False(result.HasSignatures);
        Assert.False(result.AllSignaturesValid);
        Assert.False(result.HasWarnings);
        Assert.Empty(result.Signatures);
    }

    [Fact]
    public async Task ValidateSignaturesAsync_foreign_signature_yields_hard_failure_row()
    {
        // The facade only knows how to verify XAdES; any other ISignature implementation must produce a
        // hard-fail result rather than silently passing or throwing.
        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream("payload"u8.ToArray()), "doc.txt", "text/plain");
        edoc.AddSignature(new InMemoryNonXadesSignature());

        var result = await EdocValidation.ValidateSignaturesAsync(edoc);
        Assert.True(result.HasSignatures);
        Assert.False(result.AllSignaturesValid);
        Assert.Single(result.Signatures);
        var row = result.Signatures[0];
        Assert.False(row.Result.Success);
        Assert.False(row.Result.ReferencesAndSignatureValid);
        Assert.Contains("XAdES", row.Result.Error ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ValidateSignaturesAsync_foreign_signature_sets_CertificateChainValid_to_false_when_policy_requires_chain()
    {
        // The facade pre-fills CertificateChainValid based on policy so the report-builder doesn't need a
        // second pass to decide whether chain validation was attempted.
        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream("p"u8.ToArray()), "doc.txt", "text/plain");
        edoc.AddSignature(new InMemoryNonXadesSignature());

        var withChain = await EdocValidation.ValidateSignaturesAsync(edoc,
            new SignatureTrustPolicy { ValidateCertificateChain = true });
        Assert.False(withChain.Signatures[0].Result.CertificateChainValid);

        var withoutChain = await EdocValidation.ValidateSignaturesAsync(edoc,
            new SignatureTrustPolicy { ValidateCertificateChain = false });
        Assert.Null(withoutChain.Signatures[0].Result.CertificateChainValid);
    }

    [Fact]
    public async Task ValidateSignaturesAsync_mixed_xades_and_foreign_signatures_each_get_their_own_row()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=mixed", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var edoc = Edoc.CreateNew();
        var payload = "mixed"u8.ToArray();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
        var xades = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
            cert,
            DateTimeOffset.UtcNow);
        edoc.AddSignature(xades);
        edoc.AddSignature(new InMemoryNonXadesSignature());

        var result = await EdocValidation.ValidateSignaturesAsync(edoc);
        Assert.Equal(2, result.Signatures.Count);
        Assert.Equal(0, result.Signatures[0].Ordinal);
        Assert.Equal(1, result.Signatures[1].Ordinal);
        Assert.True(result.Signatures[0].Result.Success);
        Assert.False(result.Signatures[1].Result.Success);
        Assert.False(result.AllSignaturesValid);
    }

    [Fact]
    public async Task ValidateSignaturesAsync_uses_CryptographyOnly_when_policy_omitted()
    {
        // Default policy must verify cryptography of XAdES signatures end-to-end without requiring
        // certificate chain validation. A self-signed cert is therefore acceptable under the default.
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=default-policy", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "default"u8.ToArray();
        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
        edoc.AddSignature(XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
            cert,
            DateTimeOffset.UtcNow));

        var result = await EdocValidation.ValidateSignaturesAsync(edoc);
        Assert.True(result.AllSignaturesValid);
    }

    [Fact]
    public async Task ValidateSignaturesAsync_propagates_cancellation()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=cancel", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "cancel"u8.ToArray();
        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
        edoc.AddSignature(XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
            cert,
            DateTimeOffset.UtcNow));

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            EdocValidation.ValidateSignaturesAsync(edoc, cancellationToken: cts.Token));
    }

    [Fact]
    public async Task OpenAndValidateAsync_stream_overload_wires_default_config()
    {
        // The non-config overload must defer to Edoc.OpenAndValidateAsync with EdocLibConfig.Default;
        // the behaviour difference would be invisible until someone hit the config-specific paths
        // (spill threshold, temp directory), so the regression is best surfaced as a happy-path round-trip.
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=stream", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "stream"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
            cert,
            DateTimeOffset.UtcNow);

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
        edoc.AddSignature(sig);

        using var zip = new MemoryStream();
        edoc.Save(zip);
        zip.Position = 0;

        var report = await EdocValidation.OpenAndValidateAsync(zip);
        Assert.True(report.AllSignaturesValid);
    }

    [Fact]
    public void BuildValidationReport_throws_on_null_result_or_policy()
    {
        var policy = SignatureTrustPolicy.CryptographyOnly;
        Assert.Throws<ArgumentNullException>(() =>
            ((EdocReadValidationResult)null!).BuildValidationReport(policy));
        Assert.Throws<ArgumentNullException>(() =>
            ((EdocReadValidationResult)null!).BuildValidationReport(policy, reportOptions: null));

        var empty = new EdocReadValidationResult
        {
            Edoc = Edoc.CreateNew(),
            Signatures = Array.Empty<EdocSignatureVerification>(),
        };
        Assert.Throws<ArgumentNullException>(() => empty.BuildValidationReport(null!));
        Assert.Throws<ArgumentNullException>(() => empty.BuildValidationReport(null!, reportOptions: null));
    }

    [Fact]
    public void BuildValidationReport_for_IEdocContainerValidationResult_throws_on_null()
    {
        var policy = SignatureTrustPolicy.CryptographyOnly;
        Assert.Throws<ArgumentNullException>(() =>
            ((IEdocContainerValidationResult)null!).BuildValidationReport(policy));
        Assert.Throws<ArgumentNullException>(() =>
            ((IEdocContainerValidationResult)null!).BuildValidationReport(policy, reportOptions: null));
    }

    [Fact]
    public async Task BuildValidationReport_uses_options_localizer_when_provided()
    {
        // Smoke test: a localizer that mutates a counter proves the factory walks the report tree with the
        // user-provided localizer rather than silently substituting the built-in fallback.
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=loc-report", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "loc"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
            cert,
            DateTimeOffset.UtcNow);

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
        edoc.AddSignature(sig);
        var validation = await EdocValidation.ValidateSignaturesAsync(edoc);

        var capturing = new CountingLocalizer();
        var report = validation.BuildValidationReport(SignatureTrustPolicy.CryptographyOnly,
            new ValidationReportOptions { ReportLocalizer = capturing });

        Assert.NotNull(report);
        Assert.True(capturing.Calls > 0, "Custom localizer must be consulted at least once during report build.");
    }

    [Fact]
    public void EdocReadValidationResult_HasWarnings_when_any_signature_is_indeterminate()
    {
        // Indeterminate is the canonical "not failed, not passed" verdict from PKIX/revocation gates.
        // The aggregate must surface it as a warning to differentiate from clean passes and hard failures.
        var indeterminate = new SignatureValidationResult
        {
            Success = false,
            ReferencesAndSignatureValid = true,
            CertificateChainValid = null,
            Revocation = null,
        };
        Assert.Equal(SignatureValidationIndication.Indeterminate, indeterminate.GetIndication());

        var result = new EdocReadValidationResult
        {
            Edoc = Edoc.CreateNew(),
            Signatures = new[]
            {
                new EdocSignatureVerification
                {
                    Ordinal = 0,
                    Signature = new InMemoryNonXadesSignature(),
                    Result = indeterminate,
                },
            },
        };
        Assert.True(result.HasSignatures);
        Assert.False(result.AllSignaturesValid);
        Assert.True(result.HasWarnings);
    }

    private sealed class InMemoryNonXadesSignature : ISignature
    {
        public string Id => "foreign-sig";
        public string SignatureMethod => "n/a";
        public X509Certificate? SigningCertificate => null;
        public IReadOnlyCollection<string> SignerRoles => Array.Empty<string>();
        public SignatureProductionPlace? SignatureProductionPlace => null;
        public void WriteTo(Stream stream) { /* nothing — Edoc.Save does not serialize foreign sigs */ }
    }

    private sealed class CountingLocalizer : IValidationReportLocalizer
    {
        public int Calls;
        public CultureInfo? Culture => CultureInfo.InvariantCulture;
        public string Indication(SignatureValidationIndication indication) { Calls++; return indication.ToString(); }
        public string DescribeValidationStatus(ValidationStatus status) { Calls++; return status.ToString(); }
        public string ValidationTypeCaption(ValidationType type) { Calls++; return type.ToString(); }
        public string DescribeSignatureProfile(SignatureProfile profile) { Calls++; return profile.ToString(); }
        public string DescribeSignatureQualification(SignatureQualification qualification) { Calls++; return qualification.ToString(); }
        public string DescribeCertificateQualification(CertificateQualification qualification) { Calls++; return qualification.ToString(); }
        public string DescribeTimestampQualification(TimestampQualification qualification) { Calls++; return qualification.ToString(); }
        public string DescribeValidationSignatureType(ValidationSignatureType type) { Calls++; return type.ToString(); }
        public string? LegalBasisHint(SignatureValidationIndication indication) { Calls++; return null; }
    }
}
