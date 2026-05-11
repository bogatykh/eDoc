using System.Collections.Generic;
using eDocLib.Asic.Xades;
using eDocLib.Validation;

namespace eDocLib.Validation.Reporting;

internal static partial class ValidationReportFactory
{
    private static ValidationResultNode BuildSignerRolesBranch(
        XadesSignature? signature,
        SignatureValidationResult result,
        SignatureTrustPolicy policy)
    {
        if (!policy.HasSignerClaimedRoleConstraints)
        {
            return ValidationResultNode.Leaf(
                ValidationType.SignatureSignerClaimedRoles,
                ValidationStatus.Unchecked,
                description: "Signer claimed-role constraints disabled.");
        }

        if (result.SignerClaimedRolesConstraintOk is null)
        {
            return ValidationResultNode.Leaf(
                ValidationType.SignatureSignerClaimedRoles,
                ValidationStatus.Unchecked,
                description: "Claimed-role constraints not evaluated (validation ended earlier).");
        }

        var status = result.SignerClaimedRolesConstraintOk.Value
            ? ValidationStatus.Passed
            : ValidationStatus.Failed;
        var failureReasons = status == ValidationStatus.Failed ? SingleReason(result.Error) : Array.Empty<string>();

        List<string>? roleTexts = null;
        if (signature is not null)
        {
            roleTexts = new List<string>(signature.SignerRoles.Count);
            foreach (var r in signature.SignerRoles)
            {
                roleTexts.Add(string.IsNullOrWhiteSpace(r) ? "(empty)" : r.Trim());
            }
        }

        var desc = roleTexts is null || roleTexts.Count == 0
            ? "No non-empty ClaimedRole text."
            : "Roles: " + string.Join(", ", roleTexts);

        return ValidationResultNode.Leaf(
            ValidationType.SignatureSignerClaimedRoles,
            status,
            description: desc,
            reasons: failureReasons);
    }

    private static ValidationResultNode BuildSignatureProductionPlaceBranch(XadesSignature? signature)
    {
        if (signature is null)
        {
            return ValidationResultNode.Leaf(
                ValidationType.SignatureProductionPlace,
                ValidationStatus.Unchecked,
                description: "Signature payload unavailable.");
        }

        var place = signature.SignatureProductionPlace;
        if (place is null)
        {
            return ValidationResultNode.Leaf(
                ValidationType.SignatureProductionPlace,
                ValidationStatus.Unchecked,
                description: "No SignatureProductionPlace or could not parse.");
        }

        var parts = new List<string>(4);
        if (!string.IsNullOrEmpty(place.City))
        {
            parts.Add($"City={place.City}");
        }

        if (!string.IsNullOrEmpty(place.StateOrProvince))
        {
            parts.Add($"StateOrProvince={place.StateOrProvince}");
        }

        if (!string.IsNullOrEmpty(place.PostalCode))
        {
            parts.Add($"PostalCode={place.PostalCode}");
        }

        if (!string.IsNullOrEmpty(place.CountryName))
        {
            parts.Add($"CountryName={place.CountryName}");
        }

        var desc = parts.Count == 0
            ? "SignatureProductionPlace present but all fields empty."
            : string.Join("; ", parts);

        return ValidationResultNode.Leaf(
            ValidationType.SignatureProductionPlace,
            ValidationStatus.Passed,
            description: desc);
    }
}
