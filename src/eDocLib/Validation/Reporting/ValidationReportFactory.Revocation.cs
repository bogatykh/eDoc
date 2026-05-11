using System.Collections.Generic;
using eDocLib.Revocation;
using eDocLib.Validation;

namespace eDocLib.Validation.Reporting;

internal static partial class ValidationReportFactory
{
    private static ValidationResultNode BuildRevocationBranch(SignatureValidationResult result, SignatureTrustPolicy policy)
    {
        var r = result.Revocation;
        var parts = new List<string>(8);
        var children = new List<ValidationResultNode>(3);

        ValidationStatus pkixSt;
        string pkixDesc;
        if (!policy.ValidateCertificateChain)
        {
            pkixSt = ValidationStatus.Unchecked;
            pkixDesc = "PKIX chain validation disabled; no chain revocation mode.";
        }
        else if (r?.EffectiveChainRevocationMode is { } m)
        {
            pkixSt = ValidationStatus.Passed;
            pkixDesc = $"Mode on chain build: {m}.";
            parts.Add($"PKIX revocation mode on chain build: {m}.");
        }
        else
        {
            pkixSt = ValidationStatus.Unchecked;
            pkixDesc = "No PKIX chain build or revocation mode not recorded.";
        }

        children.Add(
            ValidationResultNode.Leaf(ValidationType.SignatureRevocationPkixChainMode, pkixSt, description: pkixDesc));

        ValidationStatus embSt;
        string embDesc;
        if (!policy.VerifyUnsignedRevocationWhenPresent)
        {
            embSt = ValidationStatus.Unchecked;
            embDesc = "Verification of unsigned RevocationValues disabled by policy.";
        }
        else if (r is { EmbeddedOcspArtifactCount: 0, EmbeddedCrlArtifactCount: 0 })
        {
            embSt = ValidationStatus.Passed;
            embDesc = "No embedded OCSP/CRL blobs under RevocationValues.";
            parts.Add("Embedded RevocationValues: none.");
        }
        else
        {
            embDesc =
                $"Policy on; OCSP blobs={r!.EmbeddedOcspArtifactCount}, CRL blobs={r.EmbeddedCrlArtifactCount}. "
                + DescribeTri(result.UnsignedRevocationArtifactsValid, "cryptographic check");
            parts.Add($"Embedded RevocationValues: OCSP={r.EmbeddedOcspArtifactCount}, CRL={r.EmbeddedCrlArtifactCount}.");
            embSt = Tri(result.UnsignedRevocationArtifactsValid);
        }

        children.Add(
            BuildRevocationArtifactNode(
                branchType: ValidationType.SignatureRevocationEmbeddedUnsigned,
                artifactType: ValidationType.SignatureRevocationEmbeddedUnsignedArtifact,
                embSt,
                embDesc,
                r?.EmbeddedUnsignedArtifactOutcomes));

        ValidationStatus onlineSt;
        string onlineDesc;
        if (!policy.UsesApplicationControlledOnlineRevocation)
        {
            onlineSt = ValidationStatus.Unchecked;
            onlineDesc = "Application-controlled online revocation not configured.";
        }
        else if (r?.ApplicationOnlineFetchSkippedForSelfSignedShortChain == true)
        {
            onlineSt = ValidationStatus.Passed;
            onlineDesc = "Fetch skipped (self-signed end-entity PKIX path).";
            parts.Add("Online revocation fetch skipped (self-signed end-entity PKIX path).");
        }
        else if (result.ApplicationOnlineRevocationChecked != true)
        {
            onlineSt = ValidationStatus.Unchecked;
            onlineDesc = "Online revocation not executed (e.g. chain failed first or policy path not taken).";
        }
        else
        {
            onlineDesc =
                $"Checked={result.ApplicationOnlineRevocationChecked}; valid={DescribeNullableBool(result.ApplicationOnlineRevocationValid)}; "
                + $"non-empty OCSP={r?.HasNonEmptyOnlineFetchedRevocation == true}, "
                + $"counts OCSP={r?.OnlineFetchedOcspCount}, CRL={r?.OnlineFetchedCrlCount}.";
            parts.Add($"Online fetch: OCSP={r?.OnlineFetchedOcspCount}, CRL={r?.OnlineFetchedCrlCount}.");
            onlineSt = Tri(result.ApplicationOnlineRevocationValid);
        }

        children.Add(
            BuildRevocationArtifactNode(
                branchType: ValidationType.SignatureRevocationApplicationOnline,
                artifactType: ValidationType.SignatureRevocationApplicationOnlineArtifact,
                onlineSt,
                onlineDesc,
                r?.OnlineFetchedArtifactOutcomes));

        var st = AggregateRevocationBranchStatus(result, policy);

        return ValidationResultNode.Branch(
            ValidationType.SignatureRevocation,
            st,
            children,
            description: parts.Count > 0 ? string.Join(" ", parts) : "Revocation",
            reasons: SingleReason(result.Error));
    }

    private static ValidationResultNode BuildRevocationArtifactNode(
        ValidationType branchType,
        ValidationType artifactType,
        ValidationStatus status,
        string description,
        IReadOnlyList<RevocationArtifactOutcome>? outcomes)
    {
        if (outcomes is { Count: > 0 } list)
        {
            var n = list.Count;
            var artifactChildren = new ValidationResultNode[n];
            for (var i = 0; i < n; i++)
            {
                var o = list[i];
                artifactChildren[i] = ValidationResultNode.Leaf(
                    artifactType,
                    o.Success ? ValidationStatus.Passed : ValidationStatus.Failed,
                    description: DescribeRevocationArtifactOutcome(o));
            }

            return ValidationResultNode.Branch(branchType, status, artifactChildren, description: description);
        }

        return ValidationResultNode.Leaf(branchType, status, description: description);
    }

    private static string DescribeRevocationArtifactOutcome(RevocationArtifactOutcome o)
    {
        var label = o.Kind == RevocationArtifactKind.Ocsp ? "OCSP" : "CRL";
        return o.Success
            ? $"{label} #{o.Ordinal}: OK"
            : $"{label} #{o.Ordinal}: {o.Detail ?? "Failed"}";
    }

    private static ValidationStatus AggregateRevocationBranchStatus(SignatureValidationResult result, SignatureTrustPolicy policy)
    {
        if (!policy.ValidateCertificateChain)
        {
            return ValidationStatus.Unchecked;
        }

        if (result.UnsignedRevocationArtifactsValid == false
            || result.ApplicationOnlineRevocationValid == false)
        {
            return ValidationStatus.Failed;
        }

        if (result.CertificateChainValid == true
            && (result.UnsignedRevocationArtifactsValid is null or true)
            && (result.ApplicationOnlineRevocationValid is null or true))
        {
            return ValidationStatus.Passed;
        }

        if (result.CertificateChainValid == false)
        {
            return ValidationStatus.Failed;
        }

        return ValidationStatus.Indeterminate;
    }

    private static string DescribeTri(bool? value, string label) =>
        value switch
        {
            true => $"{label}: passed.",
            false => $"{label}: failed.",
            _ => $"{label}: not applicable or not run.",
        };

    private static string DescribeNullableBool(bool? value) =>
        value switch { true => "true", false => "false", _ => "null" };
}
