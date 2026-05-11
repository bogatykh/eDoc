using System;
using System.Collections.Generic;
using eDocLib.Validation;
using Xunit;

namespace eDocLib.Tests;

/// <summary>
/// Coverage for <see cref="SignatureValidationResult"/> as a value-bearing record: structural equality across all
/// init-only members, especially the newer TSA-trusted-list fields whose default-null state is meaningful
/// (it distinguishes "no TSL lookup ran" from "TSL lookup returned negative").
/// </summary>
public class SignatureValidationResultTests
{
    [Fact]
    public void Empty_results_are_equal()
    {
        var a = new SignatureValidationResult();
        var b = new SignatureValidationResult();
        Assert.Equal(a, b);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
    }

    [Fact]
    public void Results_differ_when_success_flips()
    {
        var ok = new SignatureValidationResult { Success = true, ReferencesAndSignatureValid = true };
        var bad = ok with { Success = false };
        Assert.NotEqual(ok, bad);
    }

    [Fact]
    public void TsaSignerCmsValid_null_vs_false_compare_distinct()
    {
        // null means "we did not run CMS verification", false means "we ran it and it failed".
        // The default record equality must preserve that distinction.
        var unran = new SignatureValidationResult { ReferencesAndSignatureValid = true };
        var ranFailed = unran with { TsaSignerCmsValid = false };
        Assert.NotEqual(unran, ranFailed);
    }

    [Fact]
    public void TimestampAuthorityListedInTrustedList_null_vs_true_distinct()
    {
        var none = new SignatureValidationResult();
        var listed = none with { TimestampAuthorityListedInTrustedList = true };
        var unlisted = none with { TimestampAuthorityListedInTrustedList = false };
        Assert.NotEqual(none, listed);
        Assert.NotEqual(listed, unlisted);
    }

    [Fact]
    public void Tsa_qualification_indicators_are_part_of_equality()
    {
        var withQ = new SignatureValidationResult
        {
            ReferencesAndSignatureValid = true,
            TimestampAuthorityListedInTrustedList = true,
            TimestampAuthorityTrustedListQualificationIndicators = new TslQualificationIndicators(
                SuggestsQualifiedElectronicSignature: false,
                SuggestsQualifiedElectronicSeal: false,
                SuggestsQualifiedTimestampService: true,
                ServiceStatusIsGranted: true),
        };
        var withNonQ = withQ with
        {
            TimestampAuthorityTrustedListQualificationIndicators = new TslQualificationIndicators(
                SuggestsQualifiedElectronicSignature: false,
                SuggestsQualifiedElectronicSeal: false,
                SuggestsQualifiedTimestampService: false,
                ServiceStatusIsGranted: true),
        };
        Assert.NotEqual(withQ, withNonQ);
    }

    [Fact]
    public void Service_type_identifiers_are_part_of_equality()
    {
        // Equality on collections in records is reference-based for IReadOnlyList<T>; the test pins the
        // expected behaviour (same reference -> equal, different reference of same contents -> unequal).
        var ids = new[] { "uri-a", "uri-b" };
        var sameRef = new SignatureValidationResult
        {
            TimestampAuthorityTrustedListServiceTypeIdentifiers = ids,
        };
        var copy = sameRef with
        {
            TimestampAuthorityTrustedListServiceTypeIdentifiers = ids,
        };
        Assert.Equal(sameRef, copy);

        var diffRef = sameRef with
        {
            TimestampAuthorityTrustedListServiceTypeIdentifiers = new[] { "uri-a", "uri-b" },
        };
        Assert.NotEqual(sameRef, diffRef);
    }

    [Fact]
    public void GetIndication_TotalPassed_when_success_is_true()
    {
        var r = new SignatureValidationResult { Success = true, ReferencesAndSignatureValid = true };
        Assert.Equal(SignatureValidationIndication.TotalPassed, r.GetIndication());
    }

    [Fact]
    public void GetIndication_TotalFailed_when_references_invalid()
    {
        var r = new SignatureValidationResult { Success = false, ReferencesAndSignatureValid = false };
        Assert.Equal(SignatureValidationIndication.TotalFailed, r.GetIndication());
    }

    [Fact]
    public void GetIndication_Indeterminate_when_references_ok_but_overall_failed()
    {
        var r = new SignatureValidationResult { Success = false, ReferencesAndSignatureValid = true };
        Assert.Equal(SignatureValidationIndication.Indeterminate, r.GetIndication());
    }

    [Fact]
    public void With_expression_preserves_unrelated_fields()
    {
        var original = new SignatureValidationResult
        {
            Success = true,
            ReferencesAndSignatureValid = true,
            TsaSignerCmsValid = true,
            TimestampAuthorityListedInTrustedList = true,
            TimestampAuthorityTrustedListServiceStatus = "http://example/granted",
        };
        var updated = original with { Success = false, Error = "post hoc" };

        Assert.True(updated.TsaSignerCmsValid);
        Assert.True(updated.TimestampAuthorityListedInTrustedList);
        Assert.Equal("http://example/granted", updated.TimestampAuthorityTrustedListServiceStatus);
        Assert.False(updated.Success);
        Assert.Equal("post hoc", updated.Error);
    }

    [Fact]
    public void Default_result_fields_are_all_null_or_false()
    {
        var r = new SignatureValidationResult();
        Assert.False(r.Success);
        Assert.Null(r.Error);
        Assert.False(r.ReferencesAndSignatureValid);
        Assert.Null(r.SignerClaimedRolesConstraintOk);
        Assert.Null(r.CertificateChainValid);
        Assert.Null(r.SignerCertificateChain);
        Assert.Null(r.SignatureTimestampImprintValid);
        Assert.Null(r.TsaSignerCmsValid);
        Assert.Null(r.TsaSignerChainValid);
        Assert.Null(r.TsaSignerCertificateChain);
        Assert.Null(r.TimestampAuthorityListedInTrustedList);
        Assert.Null(r.TimestampAuthorityTrustedListServiceTypeIdentifiers);
        Assert.Null(r.TimestampAuthorityTrustedListServiceStatus);
        Assert.Null(r.TimestampAuthorityTrustedListQualificationIndicators);
        Assert.Null(r.SigningCertificateListedInTrustedList);
        Assert.Null(r.TrustedListServiceTypeIdentifiers);
        Assert.Null(r.TrustedListServiceStatus);
        Assert.Null(r.TrustedListQualificationIndicators);
        Assert.Null(r.UnsignedRevocationArtifactsValid);
        Assert.Null(r.ApplicationOnlineRevocationChecked);
        Assert.Null(r.ApplicationOnlineRevocationValid);
        Assert.Null(r.Revocation);
    }
}
