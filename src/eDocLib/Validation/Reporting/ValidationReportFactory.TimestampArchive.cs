using System.Collections.Generic;
using eDocLib.Asic.Xades;
using eDocLib.Validation;

namespace eDocLib.Validation.Reporting;

internal static partial class ValidationReportFactory
{
    private static ValidationResultNode BuildTimestampBranch(
        XadesSignature? signature,
        SignatureValidationResult result,
        SignatureTrustPolicy policy,
        DateTimeOffset referenceNowUtc)
    {
        var primaryReasons = SingleReason(result.Error);
        var hasTs = signature is not null
            && SignatureTimestampVerifier.ContainsEmbeddedSignatureTimestamp(signature.GetSignatureOwnerDocument());

        // At most: imprint leaf + TSA CMS leaf + TSA PKIX branch/leaf (see policy blocks below).
        var children = new List<ValidationResultNode>(4);

        if (policy.TimestampImprintPolicy == SignatureTimestampImprintPolicy.RequireWhenPresent)
        {
            if (!hasTs)
            {
                children.Add(
                    ValidationResultNode.Leaf(
                        ValidationType.SignatureTimestamp,
                        ValidationStatus.Unchecked,
                        description: "No xades:SignatureTimeStamp/xades:EncapsulatedTimeStamp (XAdES-T token)."));
            }
            else
            {
                children.Add(
                    ValidationResultNode.Leaf(
                        ValidationType.SignatureTimestamp,
                        Tri(result.SignatureTimestampImprintValid),
                        reasons: primaryReasons));
            }
        }

        if (policy.ValidateTsaSigner || policy.ValidateTsaSignerChain)
        {
            if (!hasTs)
            {
                children.Add(
                    ValidationResultNode.Leaf(
                        ValidationType.SignatureTimestampSignature,
                        ValidationStatus.Unchecked,
                        description: "No embedded timestamp token."));
            }
            else
            {
                children.Add(
                    ValidationResultNode.Leaf(
                        ValidationType.SignatureTimestampSignature,
                        Tri(result.TsaSignerCmsValid),
                        reasons: primaryReasons));
            }

            if (policy.ValidateTsaSignerChain)
            {
                var tsaChainBranch = BuildTsaCertificateChainBranch(result, referenceNowUtc);
                if (tsaChainBranch is not null)
                {
                    children.Add(tsaChainBranch);
                }
                else
                {
                    children.Add(
                        ValidationResultNode.Leaf(
                            ValidationType.SignatureTimestampCertificate,
                            Tri(result.TsaSignerChainValid),
                            reasons: primaryReasons));
                }
            }
        }

        if (children.Count == 0)
        {
            return ValidationResultNode.Leaf(
                ValidationType.SignatureTimestamp,
                ValidationStatus.Unchecked,
                description: "Timestamp policies not enabled.");
        }

        if (children.Count == 1)
        {
            return children[0];
        }

        return ValidationResultNode.Branch(
            ValidationType.SignatureTimestamp,
            AggregateChildren(children),
            children);
    }

    private static ValidationResultNode? TryBuildArchiveTimestampBranch(
        XadesSignature? signature,
        SignatureValidationResult result,
        SignatureTrustPolicy policy)
    {
        var primaryReasons = SingleReason(result.Error);
        var archCount = signature is null
            ? 0
            : XadesUnsignedEmbeddedValues.ReadEncapsulatedArchiveTimeStamps(signature.GetSignatureOwnerDocument()).Count;

        if (!policy.ValidateArchiveTimeStampCms)
        {
            if (archCount == 0)
            {
                return null;
            }

            if (policy.ArchiveTimestampImprintPolicy != ArchiveTimestampImprintPolicy.RequireWhenPresent)
            {
                return ValidationResultNode.Leaf(
                    ValidationType.SignatureArchiveTimeStampSignature,
                    ValidationStatus.Unchecked,
                    description: $"{archCount} archive timestamp token(s) present; CMS verification disabled by policy.");
            }

            var cmsOffImprintOn = new List<ValidationResultNode>
            {
                ValidationResultNode.Leaf(
                    ValidationType.SignatureArchiveTimeStampSignature,
                    ValidationStatus.Unchecked,
                    description: $"{archCount} archive timestamp token(s) present; CMS verification disabled by policy."),
                ValidationResultNode.Leaf(
                    ValidationType.SignatureArchiveTimeStampImprint,
                    Tri(result.ArchiveTimeStampImprintsValid),
                    reasons: primaryReasons),
            };

            return ValidationResultNode.Branch(
                ValidationType.SignatureArchiveTimeStamp,
                AggregateChildren(cmsOffImprintOn),
                cmsOffImprintOn);
        }

        // At most: CMS (+ optional PKIX + optional imprint) or single “no token” leaf.
        var children = new List<ValidationResultNode>(4);
        if (archCount == 0)
        {
            children.Add(
                ValidationResultNode.Leaf(
                    ValidationType.SignatureArchiveTimeStampSignature,
                    ValidationStatus.Unchecked,
                    description: "No xades:ArchiveTimeStamp token."));
        }
        else
        {
            children.Add(
                ValidationResultNode.Leaf(
                    ValidationType.SignatureArchiveTimeStampSignature,
                    Tri(result.ArchiveTimeStampsCmsValid),
                    reasons: primaryReasons));
            if (policy.ValidateArchiveTimeStampChain)
            {
                children.Add(
                    ValidationResultNode.Leaf(
                        ValidationType.SignatureArchiveTimeStampCertificate,
                        Tri(result.ArchiveTimeStampsChainValid),
                        reasons: primaryReasons));
            }

            if (policy.ArchiveTimestampImprintPolicy == ArchiveTimestampImprintPolicy.RequireWhenPresent)
            {
                children.Add(
                    ValidationResultNode.Leaf(
                        ValidationType.SignatureArchiveTimeStampImprint,
                        Tri(result.ArchiveTimeStampImprintsValid),
                        reasons: primaryReasons));
            }
        }

        return children.Count == 1
            ? children[0]
            : ValidationResultNode.Branch(
                ValidationType.SignatureArchiveTimeStamp,
                AggregateChildren(children),
                children);
    }
}
