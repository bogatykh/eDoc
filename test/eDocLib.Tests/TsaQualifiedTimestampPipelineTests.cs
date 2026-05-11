using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using eDocLib.Asic.Xades;
using eDocLib.Validation;
using eDocLib.Validation.Reporting;
using Xunit;

namespace eDocLib.Tests;

/// <summary>
/// End-to-end coverage of the TSA trusted-list gating pipeline:
/// <see cref="SignatureTimestampVerifier"/> + <see cref="SignatureTrustPolicy"/> +
/// <see cref="ValidationReportFactory"/> reporting.
/// </summary>
public class TsaQualifiedTimestampPipelineTests
{
    private const string Payload = "qts-pipeline";

    [Fact]
    public async Task Default_policy_does_not_inspect_tsa_token()
    {
        var (sig, _, payload) = await CreateTimestampedSignatureAsync();
        var policy = new SignatureTrustPolicy();
        var result = await SignatureValidator.ValidateAsync(
            sig,
            new Dictionary<string, byte[]> { ["doc.txt"] = payload },
            policy);

        Assert.True(result.Success, result.Error);
        Assert.Null(result.TsaSignerCmsValid);
        Assert.Null(result.TsaSignerChainValid);
        Assert.Null(result.TimestampAuthorityListedInTrustedList);
    }

    [Fact]
    public async Task ValidateTsaSigner_alone_runs_cms_but_not_tsl_lookup()
    {
        var (sig, _, payload) = await CreateTimestampedSignatureAsync();
        var policy = new SignatureTrustPolicy { ValidateTsaSigner = true };
        var result = await SignatureValidator.ValidateAsync(
            sig,
            new Dictionary<string, byte[]> { ["doc.txt"] = payload },
            policy);

        Assert.True(result.Success, result.Error);
        Assert.True(result.TsaSignerCmsValid);
        Assert.Null(result.TsaSignerChainValid);
        Assert.Null(result.TimestampAuthorityListedInTrustedList);
    }

    [Fact]
    public async Task RequireListed_gate_engages_cms_verification_even_without_ValidateTsaSigner()
    {
        // Regression: previously a Require* TSA-TSL flag was silently ignored when ValidateTsaSigner was off.
        var (sig, tsaCert, payload) = await CreateTimestampedSignatureAsync();
        try
        {
            var index = BuildTsl((tsaCert, TslQualificationMapper.ServiceTypeTsaQTST,
                TslQualificationMapper.ServiceStatusGranted));
            var policy = new SignatureTrustPolicy
            {
                TrustedListServiceIndex = index,
                RequireTimestampAuthorityCertificateListedInTrustedList = true,
            };
            var result = await SignatureValidator.ValidateAsync(
                sig,
                new Dictionary<string, byte[]> { ["doc.txt"] = payload },
                policy);

            Assert.True(result.Success, result.Error);
            Assert.True(result.TsaSignerCmsValid);
            Assert.True(result.TimestampAuthorityListedInTrustedList);
        }
        finally
        {
            tsaCert.Dispose();
        }
    }

    [Fact]
    public async Task RequireListed_gate_without_tsl_fails_closed_even_without_ValidateTsaSigner()
    {
        var (sig, tsaCert, payload) = await CreateTimestampedSignatureAsync();
        try
        {
            var policy = new SignatureTrustPolicy
            {
                RequireTimestampAuthorityCertificateListedInTrustedList = true,
                TrustedListServiceIndex = null,
            };
            var result = await SignatureValidator.ValidateAsync(
                sig,
                new Dictionary<string, byte[]> { ["doc.txt"] = payload },
                policy);

            Assert.False(result.Success);
            Assert.Contains("TrustedListServiceIndex", result.Error!, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            tsaCert.Dispose();
        }
    }

    [Fact]
    public async Task RequireGranted_alone_fails_when_status_not_granted()
    {
        var (sig, tsaCert, payload) = await CreateTimestampedSignatureAsync();
        try
        {
            var index = BuildTsl((tsaCert, TslQualificationMapper.ServiceTypeTsaQTST,
                "http://example.invalid/non-granted"));
            var policy = new SignatureTrustPolicy
            {
                TrustedListServiceIndex = index,
                RequireTimestampAuthorityServiceStatusGranted = true,
            };
            var result = await SignatureValidator.ValidateAsync(
                sig,
                new Dictionary<string, byte[]> { ["doc.txt"] = payload },
                policy);

            Assert.False(result.Success);
            Assert.Contains("status is not granted", result.Error!, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            tsaCert.Dispose();
        }
    }

    [Fact]
    public async Task RequireQualified_alone_fails_when_listed_service_is_non_qualified_tsa()
    {
        var (sig, tsaCert, payload) = await CreateTimestampedSignatureAsync();
        try
        {
            var index = BuildTsl((tsaCert, TslQualificationMapper.ServiceTypeTsa,
                TslQualificationMapper.ServiceStatusGranted));
            var policy = new SignatureTrustPolicy
            {
                TrustedListServiceIndex = index,
                RequireQualifiedTimestampServiceType = true,
            };
            var result = await SignatureValidator.ValidateAsync(
                sig,
                new Dictionary<string, byte[]> { ["doc.txt"] = payload },
                policy);

            Assert.False(result.Success);
            Assert.Contains("qualified time-stamping service", result.Error!, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            tsaCert.Dispose();
        }
    }

    [Fact]
    public async Task All_three_gates_pass_for_qualified_granted_listed_tsa()
    {
        var (sig, tsaCert, payload) = await CreateTimestampedSignatureAsync();
        try
        {
            var index = BuildTsl((tsaCert, TslQualificationMapper.ServiceTypeTsaQTST,
                TslQualificationMapper.ServiceStatusGranted));
            var policy = new SignatureTrustPolicy
            {
                TrustedListServiceIndex = index,
                RequireTimestampAuthorityCertificateListedInTrustedList = true,
                RequireTimestampAuthorityServiceStatusGranted = true,
                RequireQualifiedTimestampServiceType = true,
            };
            var result = await SignatureValidator.ValidateAsync(
                sig,
                new Dictionary<string, byte[]> { ["doc.txt"] = payload },
                policy);

            Assert.True(result.Success, result.Error);
            Assert.True(result.TsaSignerCmsValid);
            Assert.True(result.TimestampAuthorityListedInTrustedList);
            Assert.True(result.TimestampAuthorityTrustedListQualificationIndicators!.SuggestsQualifiedTimestampService);
            Assert.True(result.TimestampAuthorityTrustedListQualificationIndicators.ServiceStatusIsGranted);
        }
        finally
        {
            tsaCert.Dispose();
        }
    }

    [Fact]
    public async Task RequireQualified_with_legacy_tssqc_uri_passes_via_lv_defaults()
    {
        var (sig, tsaCert, payload) = await CreateTimestampedSignatureAsync();
        try
        {
            var index = BuildTsl((tsaCert, TslQualificationMapper.ServiceTypeTsaTssQC,
                TslQualificationMapper.ServiceStatusGranted));
            var policy = new SignatureTrustPolicy
            {
                TrustedListServiceIndex = index,
                RequireQualifiedTimestampServiceType = true,
                MergeTrustListQualificationUriDefaults = true,
            };
            var result = await SignatureValidator.ValidateAsync(
                sig,
                new Dictionary<string, byte[]> { ["doc.txt"] = payload },
                policy);

            Assert.True(result.Success, result.Error);
            Assert.True(result.TimestampAuthorityTrustedListQualificationIndicators!.SuggestsQualifiedTimestampService);
        }
        finally
        {
            tsaCert.Dispose();
        }
    }

    [Fact]
    public async Task RequireQualified_with_legacy_tssqc_uri_fails_when_lv_defaults_disabled()
    {
        var (sig, tsaCert, payload) = await CreateTimestampedSignatureAsync();
        try
        {
            var index = BuildTsl((tsaCert, TslQualificationMapper.ServiceTypeTsaTssQC,
                TslQualificationMapper.ServiceStatusGranted));
            var policy = new SignatureTrustPolicy
            {
                TrustedListServiceIndex = index,
                RequireQualifiedTimestampServiceType = true,
                MergeTrustListQualificationUriDefaults = false,
            };
            var result = await SignatureValidator.ValidateAsync(
                sig,
                new Dictionary<string, byte[]> { ["doc.txt"] = payload },
                policy);

            Assert.False(result.Success);
            Assert.Contains("qualified time-stamping service", result.Error!, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            tsaCert.Dispose();
        }
    }

    [Fact]
    public async Task RequireListed_fails_when_tsa_cert_not_in_tsl()
    {
        var (sig, tsaCert, payload) = await CreateTimestampedSignatureAsync();
        try
        {
            using var otherRsa = RSA.Create(2048);
            var otherReq = new CertificateRequest("CN=other", otherRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var otherCert = otherReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
            var index = BuildTsl((otherCert, TslQualificationMapper.ServiceTypeTsaQTST,
                TslQualificationMapper.ServiceStatusGranted));
            var policy = new SignatureTrustPolicy
            {
                TrustedListServiceIndex = index,
                RequireTimestampAuthorityCertificateListedInTrustedList = true,
                RequireQualifiedTimestampServiceType = true,
            };
            var result = await SignatureValidator.ValidateAsync(
                sig,
                new Dictionary<string, byte[]> { ["doc.txt"] = payload },
                policy);

            Assert.False(result.Success);
            Assert.Contains("not listed", result.Error!, StringComparison.OrdinalIgnoreCase);
            Assert.False(result.TimestampAuthorityListedInTrustedList);
        }
        finally
        {
            tsaCert.Dispose();
        }
    }

    [Fact]
    public async Task Granted_status_via_extra_option_uri_passes_gate()
    {
        var (sig, tsaCert, payload) = await CreateTimestampedSignatureAsync();
        try
        {
            const string nationalStatus = "http://national.example/status/active";
            var index = BuildTsl((tsaCert, TslQualificationMapper.ServiceTypeTsaQTST, nationalStatus));
            var policy = new SignatureTrustPolicy
            {
                TrustedListServiceIndex = index,
                RequireTimestampAuthorityCertificateListedInTrustedList = true,
                RequireTimestampAuthorityServiceStatusGranted = true,
                RequireQualifiedTimestampServiceType = true,
                MergeTrustListQualificationUriDefaults = false,
                TslQualificationMappingOptions = new TslQualificationMappingOptions
                {
                    ExtraGrantedLikeServiceStatusUris = new[] { nationalStatus },
                },
            };
            var result = await SignatureValidator.ValidateAsync(
                sig,
                new Dictionary<string, byte[]> { ["doc.txt"] = payload },
                policy);

            Assert.True(result.Success, result.Error);
        }
        finally
        {
            tsaCert.Dispose();
        }
    }

    [Fact]
    public async Task Report_qualification_leaf_is_passed_only_when_listed_qualified_granted()
    {
        var (sig, tsaCert, payload) = await CreateTimestampedSignatureAsync();
        try
        {
            var index = BuildTsl((tsaCert, TslQualificationMapper.ServiceTypeTsaQTST,
                TslQualificationMapper.ServiceStatusGranted));

            var policy = new SignatureTrustPolicy
            {
                ValidateCertificateChain = false,
                TimestampImprintPolicy = SignatureTimestampImprintPolicy.RequireWhenPresent,
                ValidateTsaSigner = true,
                TrustedListServiceIndex = index,
                RequireTimestampAuthorityCertificateListedInTrustedList = true,
                RequireTimestampAuthorityServiceStatusGranted = true,
                RequireQualifiedTimestampServiceType = true,
            };

            var validator = await SignatureValidator.ValidateAsync(
                sig,
                new Dictionary<string, byte[]> { ["doc.txt"] = payload },
                policy);
            Assert.True(validator.Success, validator.Error);

            var node = FindTimestampQualificationLeaf(sig, validator, policy);
            Assert.NotNull(node);
            Assert.Equal(ValidationStatus.Passed, node!.Status);
            Assert.Contains("qualified TSA", node.Description ?? string.Empty, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("granted", node.Description ?? string.Empty, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            tsaCert.Dispose();
        }
    }

    [Fact]
    public async Task Report_qualification_leaf_is_failed_when_listed_but_not_qualified()
    {
        var (sig, tsaCert, payload) = await CreateTimestampedSignatureAsync();
        try
        {
            // Listed only as generic TSA — qualified flag required → leaf Failed.
            var index = BuildTsl((tsaCert, TslQualificationMapper.ServiceTypeTsa,
                TslQualificationMapper.ServiceStatusGranted));
            var policy = new SignatureTrustPolicy
            {
                ValidateCertificateChain = false,
                TimestampImprintPolicy = SignatureTimestampImprintPolicy.RequireWhenPresent,
                ValidateTsaSigner = true,
                TrustedListServiceIndex = index,
                RequireQualifiedTimestampServiceType = true,
            };

            var validator = await SignatureValidator.ValidateAsync(
                sig,
                new Dictionary<string, byte[]> { ["doc.txt"] = payload },
                policy);
            Assert.False(validator.Success);

            var node = FindTimestampQualificationLeaf(sig, validator, policy);
            Assert.NotNull(node);
            Assert.Equal(ValidationStatus.Failed, node!.Status);
            Assert.Contains("non-qualified TSA", node.Description ?? string.Empty, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            tsaCert.Dispose();
        }
    }

    [Fact]
    public async Task Report_qualification_leaf_is_failed_when_listed_status_not_granted()
    {
        var (sig, tsaCert, payload) = await CreateTimestampedSignatureAsync();
        try
        {
            var index = BuildTsl((tsaCert, TslQualificationMapper.ServiceTypeTsaQTST,
                "http://example.invalid/withdrawn"));
            var policy = new SignatureTrustPolicy
            {
                ValidateCertificateChain = false,
                TimestampImprintPolicy = SignatureTimestampImprintPolicy.RequireWhenPresent,
                ValidateTsaSigner = true,
                TrustedListServiceIndex = index,
                RequireTimestampAuthorityServiceStatusGranted = true,
            };

            var validator = await SignatureValidator.ValidateAsync(
                sig,
                new Dictionary<string, byte[]> { ["doc.txt"] = payload },
                policy);
            Assert.False(validator.Success);

            var node = FindTimestampQualificationLeaf(sig, validator, policy);
            Assert.NotNull(node);
            Assert.Equal(ValidationStatus.Failed, node!.Status);
            Assert.Contains("status not granted", node.Description ?? string.Empty, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            tsaCert.Dispose();
        }
    }

    [Fact]
    public async Task Report_qualification_leaf_is_failed_when_tsa_not_listed_and_listing_required()
    {
        var (sig, tsaCert, payload) = await CreateTimestampedSignatureAsync();
        try
        {
            using var otherRsa = RSA.Create(2048);
            var otherReq = new CertificateRequest("CN=other-listed", otherRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var otherCert = otherReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
            var index = BuildTsl((otherCert, TslQualificationMapper.ServiceTypeTsaQTST,
                TslQualificationMapper.ServiceStatusGranted));
            var policy = new SignatureTrustPolicy
            {
                ValidateCertificateChain = false,
                TimestampImprintPolicy = SignatureTimestampImprintPolicy.RequireWhenPresent,
                ValidateTsaSigner = true,
                TrustedListServiceIndex = index,
                RequireTimestampAuthorityCertificateListedInTrustedList = true,
            };

            var validator = await SignatureValidator.ValidateAsync(
                sig,
                new Dictionary<string, byte[]> { ["doc.txt"] = payload },
                policy);
            Assert.False(validator.Success);

            var node = FindTimestampQualificationLeaf(sig, validator, policy);
            Assert.NotNull(node);
            Assert.Equal(ValidationStatus.Failed, node!.Status);
            Assert.Contains("not listed", node.Description ?? string.Empty, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            tsaCert.Dispose();
        }
    }

    [Fact]
    public async Task Report_qualification_leaf_emitted_when_only_require_flag_set_no_validate_tsa_signer()
    {
        // Regression: report leaf must be emitted even when the user enables only TSA-TSL gates.
        var (sig, tsaCert, payload) = await CreateTimestampedSignatureAsync();
        try
        {
            var index = BuildTsl((tsaCert, TslQualificationMapper.ServiceTypeTsaQTST,
                TslQualificationMapper.ServiceStatusGranted));
            var policy = new SignatureTrustPolicy
            {
                ValidateCertificateChain = false,
                TimestampImprintPolicy = SignatureTimestampImprintPolicy.RequireWhenPresent,
                TrustedListServiceIndex = index,
                RequireQualifiedTimestampServiceType = true,
                RequireTimestampAuthorityCertificateListedInTrustedList = true,
                RequireTimestampAuthorityServiceStatusGranted = true,
            };

            var validator = await SignatureValidator.ValidateAsync(
                sig,
                new Dictionary<string, byte[]> { ["doc.txt"] = payload },
                policy);
            Assert.True(validator.Success, validator.Error);

            var node = FindTimestampQualificationLeaf(sig, validator, policy);
            Assert.NotNull(node);
            Assert.Equal(ValidationStatus.Passed, node!.Status);
        }
        finally
        {
            tsaCert.Dispose();
        }
    }

    [Fact]
    public async Task TimestampQualification_estimate_yields_QTsa_for_lv_preset_with_tsl()
    {
        var (sig, tsaCert, payload) = await CreateTimestampedSignatureAsync();
        try
        {
            using var signerRsa = RSA.Create(2048);
            var signerReq = new CertificateRequest("CN=lv-qtsa-signer", signerRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var signerCert = signerReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
            var index = BuildTsl(
                (signerCert, TslQualificationMapper.ServiceTypeQCertESign, TslQualificationMapper.ServiceStatusGranted),
                (tsaCert, TslQualificationMapper.ServiceTypeTsaQTST, TslQualificationMapper.ServiceStatusGranted));

            var policy = SignatureTrustPolicy.ForLatvianEdocLtv(index);
            // Override anchors to make chain build succeed for self-signed test certs.
            policy = new SignatureTrustPolicy
            {
                ValidateCertificateChain = policy.ValidateCertificateChain,
                RevocationMode = policy.RevocationMode,
                RequireXadesSigningCertificate = policy.RequireXadesSigningCertificate,
                TimestampImprintPolicy = policy.TimestampImprintPolicy,
                ValidateTsaSigner = policy.ValidateTsaSigner,
                ValidateTsaSignerChain = policy.ValidateTsaSignerChain,
                VerifyUnsignedRevocationWhenPresent = policy.VerifyUnsignedRevocationWhenPresent,
                TrustedListServiceIndex = policy.TrustedListServiceIndex,
                RequireSigningCertificateListedInTrustedList = policy.RequireSigningCertificateListedInTrustedList,
                RequireTrustedListServiceStatusGranted = policy.RequireTrustedListServiceStatusGranted,
                RequireTimestampAuthorityCertificateListedInTrustedList = policy.RequireTimestampAuthorityCertificateListedInTrustedList,
                RequireTimestampAuthorityServiceStatusGranted = policy.RequireTimestampAuthorityServiceStatusGranted,
                RequireQualifiedTimestampServiceType = policy.RequireQualifiedTimestampServiceType,
                MergeTrustListQualificationUriDefaults = policy.MergeTrustListQualificationUriDefaults,
                CustomTrustAnchors = new X509Certificate2Collection { signerCert, tsaCert },
                TsaTrustAnchors = new X509Certificate2Collection { tsaCert },
            };

            var sig2 = await XadesBesSigner.SignWithTimestampAsync(
                new[] { new DataFile(new MemoryStream("lv-pipeline"u8.ToArray()), "doc.txt", "text/plain") },
                signerCert,
                DateTimeOffset.UtcNow,
                new LocalSha256Rfc3161TimestampProvider());

            var result = await SignatureValidator.ValidateAsync(
                sig2,
                new Dictionary<string, byte[]> { ["doc.txt"] = "lv-pipeline"u8.ToArray() },
                policy);

            Assert.True(result.Success, result.Error);
            Assert.Equal(
                TimestampQualification.QTsa,
                ValidationReportQualifications.EstimateTimestampQualification(policy, result));
        }
        finally
        {
            tsaCert.Dispose();
        }
    }

    [Fact]
    public async Task EstimateTimestampQualification_returns_QTsa_when_only_require_qualified_set_imprint_disabled()
    {
        // Regression: prior to the fix, EstimateTimestampQualification.wantSig was
        // (ValidateTsaSigner || ValidateTsaSignerChain || ImprintPolicy == RequireWhenPresent).
        // A host that enabled qualified-TSA TSL gates only and disabled imprint policy explicitly would
        // see TimestampQualification.Unknown even though CMS verification ran (validator forces it).
        var (sig, tsaCert, payload) = await CreateTimestampedSignatureAsync();
        try
        {
            var index = BuildTsl((tsaCert, TslQualificationMapper.ServiceTypeTsaQTST,
                TslQualificationMapper.ServiceStatusGranted));
            var policy = new SignatureTrustPolicy
            {
                ValidateCertificateChain = false,
                TimestampImprintPolicy = SignatureTimestampImprintPolicy.Ignore,
                TrustedListServiceIndex = index,
                RequireTimestampAuthorityCertificateListedInTrustedList = true,
                RequireTimestampAuthorityServiceStatusGranted = true,
                RequireQualifiedTimestampServiceType = true,
            };

            var result = await SignatureValidator.ValidateAsync(
                sig,
                new Dictionary<string, byte[]> { ["doc.txt"] = payload },
                policy);

            Assert.True(result.Success, result.Error);
            Assert.True(result.TsaSignerCmsValid);
            Assert.Null(result.SignatureTimestampImprintValid);
            Assert.Equal(
                TimestampQualification.QTsa,
                ValidationReportQualifications.EstimateTimestampQualification(policy, result));
        }
        finally
        {
            tsaCert.Dispose();
        }
    }

    [Fact]
    public async Task EstimateTimestampQualification_returns_Tsa_when_only_validate_tsa_signer_chain_set_without_imprint()
    {
        // Without trusted-list evidence, only CMS verification of the TSA succeeds; qualification falls back to Tsa.
        var (sig, _, payload) = await CreateTimestampedSignatureAsync();
        var policy = new SignatureTrustPolicy
        {
            ValidateCertificateChain = false,
            TimestampImprintPolicy = SignatureTimestampImprintPolicy.Ignore,
            ValidateTsaSigner = true,
        };

        var result = await SignatureValidator.ValidateAsync(
            sig,
            new Dictionary<string, byte[]> { ["doc.txt"] = payload },
            policy);

        Assert.True(result.Success, result.Error);
        Assert.True(result.TsaSignerCmsValid);
        Assert.Equal(
            TimestampQualification.Tsa,
            ValidationReportQualifications.EstimateTimestampQualification(policy, result));
    }

    [Fact]
    public void EstimateTimestampQualification_returns_Unknown_for_neutral_policy_even_with_stamped_result()
    {
        // A test-constructed result that ostensibly carries TsaSignerCmsValid=true cannot upgrade qualification
        // unless the policy itself asked for token inspection or imprint verification. This guards against an
        // accidental relaxation when refactoring wantSig.
        var policy = new SignatureTrustPolicy
        {
            TimestampImprintPolicy = SignatureTimestampImprintPolicy.Ignore,
        };
        var result = new SignatureValidationResult
        {
            Success = true,
            ReferencesAndSignatureValid = true,
            TsaSignerCmsValid = true,
            TimestampAuthorityListedInTrustedList = true,
            TimestampAuthorityTrustedListQualificationIndicators = new TslQualificationIndicators(
                SuggestsQualifiedElectronicSignature: false,
                SuggestsQualifiedElectronicSeal: false,
                SuggestsQualifiedTimestampService: true,
                ServiceStatusIsGranted: true),
        };

        Assert.Equal(
            TimestampQualification.Unknown,
            ValidationReportQualifications.EstimateTimestampQualification(policy, result));
    }

    [Fact]
    public async Task Report_cms_leaf_emitted_when_only_require_flag_set_no_validate_tsa_signer()
    {
        // Regression: BuildTimestampBranch previously gated the SignatureTimestampSignature (CMS) leaf on
        // ValidateTsaSigner / ValidateTsaSignerChain only. With qualified-TSA TSL gates now forcing CMS verification,
        // the report must include the CMS leaf so a reader can see the verification actually ran.
        var (sig, tsaCert, payload) = await CreateTimestampedSignatureAsync();
        try
        {
            var index = BuildTsl((tsaCert, TslQualificationMapper.ServiceTypeTsaQTST,
                TslQualificationMapper.ServiceStatusGranted));
            var policy = new SignatureTrustPolicy
            {
                ValidateCertificateChain = false,
                TimestampImprintPolicy = SignatureTimestampImprintPolicy.RequireWhenPresent,
                TrustedListServiceIndex = index,
                RequireQualifiedTimestampServiceType = true,
                RequireTimestampAuthorityCertificateListedInTrustedList = true,
                RequireTimestampAuthorityServiceStatusGranted = true,
            };

            var validator = await SignatureValidator.ValidateAsync(
                sig,
                new Dictionary<string, byte[]> { ["doc.txt"] = payload },
                policy);
            Assert.True(validator.Success, validator.Error);

            var cms = FindFirstNodeOfType(sig, validator, policy, ValidationType.SignatureTimestampSignature);
            Assert.NotNull(cms);
            Assert.Equal(ValidationStatus.Passed, cms!.Status);
        }
        finally
        {
            tsaCert.Dispose();
        }
    }

    [Fact]
    public async Task Report_cms_leaf_absent_when_no_TSA_inspection_requested()
    {
        // Counterpart of the above regression: when neither ValidateTsaSigner nor Require* flags are set,
        // the CMS leaf must NOT appear in the report (it would be misleading — CMS verification did not run).
        var (sig, _, payload) = await CreateTimestampedSignatureAsync();
        var policy = new SignatureTrustPolicy
        {
            ValidateCertificateChain = false,
            TimestampImprintPolicy = SignatureTimestampImprintPolicy.RequireWhenPresent,
        };

        var validator = await SignatureValidator.ValidateAsync(
            sig,
            new Dictionary<string, byte[]> { ["doc.txt"] = payload },
            policy);
        Assert.True(validator.Success, validator.Error);

        var cms = FindFirstNodeOfType(sig, validator, policy, ValidationType.SignatureTimestampSignature);
        Assert.Null(cms);
    }

    [Fact]
    public async Task TryVerifyTimeStampTokenDerAsync_completes_async_path_with_dotnet_tsa_alive()
    {
        // Regression: TryVerifyTimeStampTokenDerAsync used to be a non-async method that built X509Certificate2
        // inside a `using` block and returned an async Task before that block exited, disposing the certificate
        // before the awaited online-revocation path could read it. The fix makes the method async; this test
        // exercises the verifyChain=true async path and asserts a coherent success outcome.
        var (sig, _, _) = await CreateTimestampedSignatureAsync();
        var policy = new SignatureTrustPolicy
        {
            ValidateTsaSigner = true,
            ValidateTsaSignerChain = true,
            TsaTrustAnchors = new X509Certificate2Collection(LocalSha256Rfc3161TimestampProvider.EmbeddedTsaCertificate),
        };

        var outcome = await SignatureTimestampVerifier.TryVerifyTsaTokenTrustAsync(
            sig.GetSignatureOwnerDocument(),
            policy);

        Assert.True(outcome.Ok, outcome.Error);
        Assert.True(outcome.CmsValid);
        Assert.True(outcome.ChainValid);
        Assert.NotNull(outcome.CertificateChain);
    }

    private static ValidationResultNode? FindFirstNodeOfType(
        XadesSignature signature,
        SignatureValidationResult result,
        SignatureTrustPolicy policy,
        ValidationType type)
    {
        var report = ValidationReportFactory.CreateForSignature(
            ordinal: 0,
            signature: signature,
            result: result,
            policy: policy);
        return FindFirst(report.Tree, type);
    }

    private static ValidationResultNode? FindTimestampQualificationLeaf(
        XadesSignature signature,
        SignatureValidationResult result,
        SignatureTrustPolicy policy)
    {
        var report = ValidationReportFactory.CreateForSignature(
            ordinal: 0,
            signature: signature,
            result: result,
            policy: policy);

        return FindFirst(report.Tree, ValidationType.SignatureTimestampQualification);
    }

    private static ValidationResultNode? FindFirst(ValidationResultNode node, ValidationType type)
    {
        if (node.Type == type)
        {
            return node;
        }

        foreach (var c in node.Children)
        {
            var match = FindFirst(c, type);
            if (match is not null)
            {
                return match;
            }
        }

        return null;
    }

    private static async Task<(XadesSignature Signature, X509Certificate2 TsaCert, byte[] Payload)>
        CreateTimestampedSignatureAsync()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=qts-pipeline", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = Encoding.UTF8.GetBytes(Payload);
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var sig = await XadesBesSigner.SignWithTimestampAsync(
            dfs,
            cert,
            DateTimeOffset.Parse("2025-03-01T00:00:00Z"),
            new LocalSha256Rfc3161TimestampProvider());

        return (sig, LocalSha256Rfc3161TimestampProvider.EmbeddedTsaCertificate, payload);
    }

    private static TrustedListServiceIndex BuildTsl(
        params (X509Certificate2 Certificate, string ServiceType, string ServiceStatus)[] entries)
    {
        var sb = new StringBuilder();
        foreach (var (cert, type, status) in entries)
        {
            var b64 = Convert.ToBase64String(cert.Export(X509ContentType.Cert));
            sb.Append($"""
                <TSPService>
                  <ServiceInformation>
                    <ServiceTypeIdentifier>{type}</ServiceTypeIdentifier>
                    <ServiceStatus>{status}</ServiceStatus>
                    <ServiceDigitalIdentity>
                      <DigitalId><X509Certificate>{b64}</X509Certificate></DigitalId>
                    </ServiceDigitalIdentity>
                  </ServiceInformation>
                </TSPService>
                """);
        }

        var xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
              {sb}
            </TrustServiceStatusList>
            """;
        return TrustedListServiceIndex.FromStream(new MemoryStream(Encoding.UTF8.GetBytes(xml)));
    }
}
