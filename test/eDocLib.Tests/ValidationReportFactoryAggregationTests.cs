using System.Linq;
using eDocLib.Validation;
using eDocLib.Validation.Reporting;
using Xunit;

namespace eDocLib.Tests;

/// <summary>
/// Targeted coverage for <see cref="ValidationReportFactory"/> aggregation and indication mapping. These tests
/// drive synthesized <see cref="SignatureValidationResult"/> values through the public reporting surface to verify
/// the three-state outcome (Passed / Failed / Indeterminate) propagates the way the validator intends, and that
/// crypto-layer reasons surface as node reasons when the cryptographic core fails.
/// </summary>
public class ValidationReportFactoryAggregationTests
{
    [Fact]
    public void Signature_node_is_Passed_when_overall_success_and_references_valid()
    {
        var result = new SignatureValidationResult
        {
            Success = true,
            ReferencesAndSignatureValid = true,
        };
        var report = ValidationReportFactory.CreateForSignature(
            ordinal: 0,
            signature: null,
            result: result,
            policy: SignatureTrustPolicy.CryptographyOnly);

        Assert.Equal(SignatureValidationIndication.TotalPassed, report.Indication);
        Assert.Equal(ValidationType.Signature, report.Tree.Type);
        Assert.Equal(ValidationStatus.Passed, report.Tree.Status);
    }

    [Fact]
    public void Signature_node_is_Failed_when_references_invalid()
    {
        var result = new SignatureValidationResult
        {
            Success = false,
            Error = "Reference digest mismatch.",
            ReferencesAndSignatureValid = false,
        };
        var report = ValidationReportFactory.CreateForSignature(
            ordinal: 0,
            signature: null,
            result: result,
            policy: SignatureTrustPolicy.CryptographyOnly);

        Assert.Equal(SignatureValidationIndication.TotalFailed, report.Indication);
        Assert.Equal(ValidationStatus.Failed, report.Tree.Status);

        // Crypto-layer nodes (method, refs, value, signing cert refs) propagate the same Failed status with the error reason.
        var methodNode = FindFirst(report.Tree, ValidationType.SignatureMethod);
        Assert.NotNull(methodNode);
        Assert.Equal(ValidationStatus.Failed, methodNode!.Status);
        Assert.Contains("Reference digest mismatch.", methodNode.Reasons);
    }

    [Fact]
    public void Signature_node_is_Indeterminate_when_references_ok_but_overall_failed()
    {
        // Cryptographic core OK but a higher-layer policy (trust / chain / TSL) refused the signature.
        var result = new SignatureValidationResult
        {
            Success = false,
            Error = "TSL service status is not granted.",
            ReferencesAndSignatureValid = true,
        };
        var report = ValidationReportFactory.CreateForSignature(
            ordinal: 0,
            signature: null,
            result: result,
            policy: SignatureTrustPolicy.CryptographyOnly);

        Assert.Equal(SignatureValidationIndication.Indeterminate, report.Indication);
        Assert.Equal(ValidationStatus.Indeterminate, report.Tree.Status);

        // Crypto-layer leaves stay Passed (the failure is at a higher layer).
        var methodNode = FindFirst(report.Tree, ValidationType.SignatureMethod);
        Assert.NotNull(methodNode);
        Assert.Equal(ValidationStatus.Passed, methodNode!.Status);
        Assert.Empty(methodNode.Reasons);
    }

    [Fact]
    public void Signature_subtree_emits_type_profile_method_in_documented_order()
    {
        // The tree shape order is part of the public report contract because downstream consumers iterate it.
        var result = new SignatureValidationResult
        {
            Success = true,
            ReferencesAndSignatureValid = true,
        };
        var report = ValidationReportFactory.CreateForSignature(
            ordinal: 0,
            signature: null,
            result: result,
            policy: SignatureTrustPolicy.CryptographyOnly);

        var types = report.Tree.Children.Select(c => c.Type).ToList();
        var typeIdx = types.IndexOf(ValidationType.SignatureType);
        var profileIdx = types.IndexOf(ValidationType.SignatureProfile);
        var methodIdx = types.IndexOf(ValidationType.SignatureMethod);
        Assert.True(typeIdx >= 0 && profileIdx > typeIdx && methodIdx > profileIdx,
            $"Unexpected child order: [{string.Join(", ", types)}].");
    }

    [Fact]
    public void Timestamp_branch_is_Unchecked_when_no_timestamp_related_policy()
    {
        // CryptographyOnly disables imprint policy entirely, so the timestamp branch collapses to a single
        // 'Unchecked / Timestamp policies not enabled.' leaf rather than a parent branch with no children.
        var policy = new SignatureTrustPolicy
        {
            ValidateCertificateChain = false,
            TimestampImprintPolicy = SignatureTimestampImprintPolicy.Ignore,
        };
        var result = new SignatureValidationResult
        {
            Success = true,
            ReferencesAndSignatureValid = true,
        };
        var report = ValidationReportFactory.CreateForSignature(
            ordinal: 0,
            signature: null,
            result: result,
            policy: policy);

        var ts = FindFirst(report.Tree, ValidationType.SignatureTimestamp);
        Assert.NotNull(ts);
        Assert.Equal(ValidationStatus.Unchecked, ts!.Status);
        Assert.Contains("Timestamp policies not enabled", ts.Description ?? string.Empty);
    }

    [Fact]
    public void Cms_timestamp_leaf_is_Unchecked_when_no_token_present()
    {
        // ValidateTsaSigner=true but the synthetic null signature has no embedded timestamp -> Unchecked, not Failed.
        var policy = new SignatureTrustPolicy
        {
            ValidateCertificateChain = false,
            TimestampImprintPolicy = SignatureTimestampImprintPolicy.Ignore,
            ValidateTsaSigner = true,
        };
        var result = new SignatureValidationResult
        {
            Success = true,
            ReferencesAndSignatureValid = true,
        };
        var report = ValidationReportFactory.CreateForSignature(
            ordinal: 0,
            signature: null,
            result: result,
            policy: policy);

        var cms = FindFirst(report.Tree, ValidationType.SignatureTimestampSignature);
        Assert.NotNull(cms);
        Assert.Equal(ValidationStatus.Unchecked, cms!.Status);
        Assert.Contains("No embedded timestamp token", cms.Description ?? string.Empty);
    }

    [Fact]
    public void Report_uses_default_localizer_when_options_omit_one()
    {
        var result = new SignatureValidationResult
        {
            Success = true,
            ReferencesAndSignatureValid = true,
        };
        var report = ValidationReportFactory.CreateForSignature(
            ordinal: 0,
            signature: null,
            result: result,
            policy: SignatureTrustPolicy.CryptographyOnly);

        var typeNode = FindFirst(report.Tree, ValidationType.SignatureType);
        Assert.NotNull(typeNode);
        // Default localizer formats Unknown as "Unknown".
        Assert.Equal("Unknown", typeNode!.Description);
    }

    [Fact]
    public void Report_consumes_custom_localizer_for_validation_type_caption()
    {
        // ValidationType captions surface in tree consumers (toString formatters, UI labels).
        var overrides = new System.Collections.Generic.Dictionary<string, string>
        {
            ["ValidationSignatureType.UnknownType"] = "custom-unknown",
        };
        var loc = new DictionaryValidationReportLocalizer(overrides);
        var result = new SignatureValidationResult
        {
            Success = true,
            ReferencesAndSignatureValid = true,
        };
        var report = ValidationReportFactory.CreateForSignature(
            ordinal: 0,
            signature: null,
            result: result,
            policy: SignatureTrustPolicy.CryptographyOnly,
            reportOptions: null,
            reportLocalizer: loc);

        var typeNode = FindFirst(report.Tree, ValidationType.SignatureType);
        Assert.NotNull(typeNode);
        Assert.Equal("custom-unknown", typeNode!.Description);
    }

    [Fact]
    public void CreateForSignature_requires_non_null_result_and_policy()
    {
        Assert.Throws<System.ArgumentNullException>(() => ValidationReportFactory.CreateForSignature(
            ordinal: 0,
            signature: null,
            result: null!,
            policy: SignatureTrustPolicy.CryptographyOnly));

        Assert.Throws<System.ArgumentNullException>(() => ValidationReportFactory.CreateForSignature(
            ordinal: 0,
            signature: null,
            result: new SignatureValidationResult(),
            policy: null!));
    }

    [Fact]
    public void Crypto_failure_propagates_reasons_to_all_crypto_layer_leaves()
    {
        // When ReferencesAndSignatureValid=false, every crypto-layer leaf should carry the primary error reason
        // so a tree-walker can collect the failure context without scanning the parent.
        var result = new SignatureValidationResult
        {
            Success = false,
            Error = "Signature value did not verify with the signer key.",
            ReferencesAndSignatureValid = false,
        };
        var report = ValidationReportFactory.CreateForSignature(
            ordinal: 0,
            signature: null,
            result: result,
            policy: SignatureTrustPolicy.CryptographyOnly);

        var cryptoTypes = new[]
        {
            ValidationType.SignatureMethod,
            ValidationType.SignatureEdocDataObjectReferences,
            ValidationType.SignatureValue,
            ValidationType.SignatureEdocSigningCertificateReferences,
        };
        foreach (var t in cryptoTypes)
        {
            var node = FindFirst(report.Tree, t);
            Assert.NotNull(node);
            Assert.Equal(ValidationStatus.Failed, node!.Status);
            Assert.Contains("Signature value did not verify", string.Join(" | ", node.Reasons));
        }
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
}
