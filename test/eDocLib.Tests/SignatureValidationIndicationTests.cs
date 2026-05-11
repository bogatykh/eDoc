using eDocLib.Validation;
using Xunit;

namespace eDocLib.Tests;

/// <summary>
/// Coverage for <see cref="SignatureValidationIndicationExtensions.GetIndication"/>: pins the three-state
/// mapping that downstream UI and report builders rely on. The contract is order-dependent — Success short-circuits
/// before ReferencesAndSignatureValid is consulted — so altering the priority would silently relabel reports.
/// </summary>
public class SignatureValidationIndicationTests
{
    [Fact]
    public void Success_true_maps_to_TotalPassed()
    {
        var r = new SignatureValidationResult
        {
            Success = true,
            ReferencesAndSignatureValid = true,
        };
        Assert.Equal(SignatureValidationIndication.TotalPassed, r.GetIndication());
    }

    [Fact]
    public void Success_false_and_references_false_maps_to_TotalFailed()
    {
        // Core XML-DSig failure: reference digest or signature value mismatch.
        var r = new SignatureValidationResult
        {
            Success = false,
            ReferencesAndSignatureValid = false,
        };
        Assert.Equal(SignatureValidationIndication.TotalFailed, r.GetIndication());
    }

    [Fact]
    public void Success_false_and_references_true_maps_to_Indeterminate()
    {
        // Crypto verified but a policy gate (chain, TSL, timestamp imprint, role allow-list) failed.
        var r = new SignatureValidationResult
        {
            Success = false,
            ReferencesAndSignatureValid = true,
        };
        Assert.Equal(SignatureValidationIndication.Indeterminate, r.GetIndication());
    }

    [Fact]
    public void Role_constraint_failure_surfaces_as_Indeterminate()
    {
        // Regression check on the wiring used by EdocReadValidationResult.HasWarnings: a role-allow-list
        // mismatch must be reported as Indeterminate, not TotalFailed.
        var r = new SignatureValidationResult
        {
            Success = false,
            Error = "Claimed signer role 'X' is not allowed by policy.",
            ReferencesAndSignatureValid = true,
            SignerClaimedRolesConstraintOk = false,
        };
        Assert.Equal(SignatureValidationIndication.Indeterminate, r.GetIndication());
    }

    [Fact]
    public void Chain_failure_surfaces_as_Indeterminate()
    {
        var r = new SignatureValidationResult
        {
            Success = false,
            Error = "Certificate chain validation failed.",
            ReferencesAndSignatureValid = true,
            CertificateChainValid = false,
        };
        Assert.Equal(SignatureValidationIndication.Indeterminate, r.GetIndication());
    }

    [Fact]
    public void Success_true_with_inconsistent_references_false_still_returns_TotalPassed()
    {
        // Documents the explicit priority order: Success short-circuits. This state shouldn't be produced
        // by the validator, but the contract is that GetIndication respects Success as the final authority.
        var r = new SignatureValidationResult
        {
            Success = true,
            ReferencesAndSignatureValid = false,
        };
        Assert.Equal(SignatureValidationIndication.TotalPassed, r.GetIndication());
    }
}
