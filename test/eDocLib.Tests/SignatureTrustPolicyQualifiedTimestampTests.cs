using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using eDocLib.Validation;
using Xunit;

namespace eDocLib.Tests;

public class SignatureTrustPolicyQualifiedTimestampTests
{
    [Fact]
    public void RequiresTsaTokenInspection_is_false_for_default_policy()
    {
        var policy = new SignatureTrustPolicy();
        Assert.False(policy.RequiresTsaTokenInspection);
    }

    [Theory]
    [InlineData(nameof(SignatureTrustPolicy.ValidateTsaSigner))]
    [InlineData(nameof(SignatureTrustPolicy.ValidateTsaSignerChain))]
    [InlineData(nameof(SignatureTrustPolicy.RequireTimestampAuthorityCertificateListedInTrustedList))]
    [InlineData(nameof(SignatureTrustPolicy.RequireTimestampAuthorityServiceStatusGranted))]
    [InlineData(nameof(SignatureTrustPolicy.RequireQualifiedTimestampServiceType))]
    public void RequiresTsaTokenInspection_is_true_when_any_tsa_flag_set(string flagName) =>
        Assert.True(BuildPolicyWithSingleFlag(flagName).RequiresTsaTokenInspection);

    [Fact]
    public void CryptographyOnly_does_not_require_tsa_inspection()
    {
        Assert.False(SignatureTrustPolicy.CryptographyOnly.RequiresTsaTokenInspection);
    }

    [Fact]
    public void CryptographyAndTimestampImprint_does_not_require_tsa_inspection()
    {
        Assert.False(SignatureTrustPolicy.CryptographyAndTimestampImprint.RequiresTsaTokenInspection);
    }

    [Fact]
    public void CryptographyTimestampImprintAndTsaSigner_requires_tsa_inspection()
    {
        Assert.True(SignatureTrustPolicy.CryptographyTimestampImprintAndTsaSigner.RequiresTsaTokenInspection);
    }

    [Fact]
    public void ForLatvianEdocLtv_without_tsl_does_not_enable_tsl_require_flags()
    {
        var policy = SignatureTrustPolicy.ForLatvianEdocLtv();
        Assert.False(policy.RequireSigningCertificateListedInTrustedList);
        Assert.False(policy.RequireTrustedListServiceStatusGranted);
        Assert.False(policy.RequireTimestampAuthorityCertificateListedInTrustedList);
        Assert.False(policy.RequireTimestampAuthorityServiceStatusGranted);
        Assert.False(policy.RequireQualifiedTimestampServiceType);
        Assert.True(policy.RequiresTsaTokenInspection); // because ValidateTsaSigner is on
    }

    [Fact]
    public void ForLatvianEdocLtv_with_tsl_enables_all_three_tsa_gates()
    {
        var index = BuildSingleEntryTsl();
        var policy = SignatureTrustPolicy.ForLatvianEdocLtv(index);

        Assert.True(policy.RequireTimestampAuthorityCertificateListedInTrustedList);
        Assert.True(policy.RequireTimestampAuthorityServiceStatusGranted);
        Assert.True(policy.RequireQualifiedTimestampServiceType);
    }

    [Fact]
    public void ForLatvianEdocLtv_propagates_reference_time_when_supplied()
    {
        var index = BuildSingleEntryTsl();
        var t = DateTimeOffset.Parse("2024-01-15T00:00:00Z");
        var policy = SignatureTrustPolicy.ForLatvianEdocLtv(index, t);
        Assert.Equal(t, policy.TrustedListQualificationReferenceTimeUtc);
    }

    [Fact]
    public void ForLatvianEdocLtv_merges_national_qualification_uri_defaults_by_default()
    {
        var policy = SignatureTrustPolicy.ForLatvianEdocLtv();
        Assert.True(policy.MergeTrustListQualificationUriDefaults);
        var resolved = policy.ResolveQualificationMappingOptions();
        Assert.NotNull(resolved);
        Assert.Contains(
            TslQualificationMapper.ServiceStatusAccredited,
            resolved!.ExtraGrantedLikeServiceStatusUris!,
            StringComparer.OrdinalIgnoreCase);
        Assert.Contains(
            TslQualificationMapper.ServiceTypeTsaTssQC,
            resolved.ExtraQualifiedTimestampServiceTypeUris!,
            StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void ResolveQualificationMappingOptions_returns_null_when_no_defaults_and_no_options()
    {
        var policy = new SignatureTrustPolicy
        {
            MergeTrustListQualificationUriDefaults = false,
            TslQualificationMappingOptions = null,
        };
        Assert.Null(policy.ResolveQualificationMappingOptions());
    }

    [Fact]
    public void ResolveQualificationMappingOptions_returns_only_user_options_when_defaults_disabled()
    {
        var policy = new SignatureTrustPolicy
        {
            MergeTrustListQualificationUriDefaults = false,
            TslQualificationMappingOptions = new TslQualificationMappingOptions
            {
                ExtraQualifiedTimestampServiceTypeUris = new[] { "http://host/qtsa" },
            },
        };
        var opt = policy.ResolveQualificationMappingOptions();
        Assert.NotNull(opt);
        Assert.Equal("http://host/qtsa", Assert.Single(opt!.ExtraQualifiedTimestampServiceTypeUris!));
        Assert.Null(opt.ExtraGrantedLikeServiceStatusUris);
    }

    [Fact]
    public void ResolveQualificationMappingOptions_merges_user_options_with_lv_defaults_when_enabled()
    {
        var policy = new SignatureTrustPolicy
        {
            MergeTrustListQualificationUriDefaults = true,
            TslQualificationMappingOptions = new TslQualificationMappingOptions
            {
                ExtraQualifiedTimestampServiceTypeUris = new[] { "http://host/qtsa" },
            },
        };
        var opt = policy.ResolveQualificationMappingOptions();
        Assert.NotNull(opt);
        Assert.Contains("http://host/qtsa", opt!.ExtraQualifiedTimestampServiceTypeUris!, StringComparer.OrdinalIgnoreCase);
        Assert.Contains(
            TslQualificationMapper.ServiceTypeTsaTssQC,
            opt.ExtraQualifiedTimestampServiceTypeUris!,
            StringComparer.OrdinalIgnoreCase);
    }

    private static SignatureTrustPolicy BuildPolicyWithSingleFlag(string flagName) => flagName switch
    {
        nameof(SignatureTrustPolicy.ValidateTsaSigner) =>
            new SignatureTrustPolicy { ValidateTsaSigner = true },
        nameof(SignatureTrustPolicy.ValidateTsaSignerChain) =>
            new SignatureTrustPolicy { ValidateTsaSignerChain = true },
        nameof(SignatureTrustPolicy.RequireTimestampAuthorityCertificateListedInTrustedList) =>
            new SignatureTrustPolicy { RequireTimestampAuthorityCertificateListedInTrustedList = true },
        nameof(SignatureTrustPolicy.RequireTimestampAuthorityServiceStatusGranted) =>
            new SignatureTrustPolicy { RequireTimestampAuthorityServiceStatusGranted = true },
        nameof(SignatureTrustPolicy.RequireQualifiedTimestampServiceType) =>
            new SignatureTrustPolicy { RequireQualifiedTimestampServiceType = true },
        _ => throw new ArgumentOutOfRangeException(nameof(flagName), flagName, "Unhandled flag"),
    };

    private static TrustedListServiceIndex BuildSingleEntryTsl()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=policy-tests", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var b64 = Convert.ToBase64String(cert.Export(X509ContentType.Cert));
        var xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
              <TSPService>
                <ServiceInformation>
                  <ServiceTypeIdentifier>{TslQualificationMapper.ServiceTypeTsaQTST}</ServiceTypeIdentifier>
                  <ServiceStatus>{TslQualificationMapper.ServiceStatusGranted}</ServiceStatus>
                  <ServiceDigitalIdentity>
                    <DigitalId><X509Certificate>{b64}</X509Certificate></DigitalId>
                  </ServiceDigitalIdentity>
                </ServiceInformation>
              </TSPService>
            </TrustServiceStatusList>
            """;
        return TrustedListServiceIndex.FromStream(new MemoryStream(Encoding.UTF8.GetBytes(xml)));
    }
}
