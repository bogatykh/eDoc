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

        // At most: imprint leaf + TSA CMS leaf + TSA PKIX branch/leaf + TSA TSL qualification leaf.
        var children = new List<ValidationResultNode>(5);

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

        // CMS verification runs whenever any TSA token inspection is requested (including TSA-TSL gates
        // that implicitly force CMS verification). Emit the CMS leaf so the report reflects the work the
        // validator actually performed; previously only ValidateTsaSigner/Chain gated this leaf, which
        // hid CMS evidence when a host enabled qualified-TSA gates without also setting ValidateTsaSigner.
        if (policy.RequiresTsaTokenInspection)
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

        var qualificationNode = BuildTimestampQualificationLeaf(result, policy, hasTs, primaryReasons);
        if (qualificationNode is not null)
        {
            children.Add(qualificationNode);
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

    /// <summary>
    /// Emits the trusted-list timestamp qualification leaf when the policy queried the TSL for the TSA certificate.
    /// Returns <c>null</c> when no TSL lookup ran for the TSA (no embedded timestamp, no TSL index, or imprint-only policy).
    /// </summary>
    private static ValidationResultNode? BuildTimestampQualificationLeaf(
        SignatureValidationResult result,
        SignatureTrustPolicy policy,
        bool hasTs,
        IReadOnlyList<string> primaryReasons)
    {
        var tslConsulted = policy.TrustedListServiceIndex is not null
            && policy.RequiresTsaTokenInspection;
        if (!tslConsulted)
        {
            return null;
        }

        if (!hasTs)
        {
            return ValidationResultNode.Leaf(
                ValidationType.SignatureTimestampQualification,
                ValidationStatus.Unchecked,
                description: "No embedded timestamp token.");
        }

        if (result.TimestampAuthorityListedInTrustedList is null)
        {
            return null;
        }

        var listed = result.TimestampAuthorityListedInTrustedList == true;
        var ind = result.TimestampAuthorityTrustedListQualificationIndicators;
        var qualified = ind?.SuggestsQualifiedTimestampService == true;
        var granted = ind?.ServiceStatusIsGranted == true;

        var status = listed && qualified && granted
            ? ValidationStatus.Passed
            : DetermineQualificationFailureStatus(policy, listed, qualified, granted);

        var description = listed
            ? FormatQualificationDescription(qualified, granted, result.TimestampAuthorityTrustedListServiceStatus)
            : "TSA certificate not listed in the configured trusted service list.";

        return ValidationResultNode.Leaf(
            ValidationType.SignatureTimestampQualification,
            status,
            description: description,
            reasons: status == ValidationStatus.Failed ? primaryReasons : Array.Empty<string>());
    }

    private static ValidationStatus DetermineQualificationFailureStatus(
        SignatureTrustPolicy policy,
        bool listed,
        bool qualified,
        bool granted)
    {
        if (!listed && policy.RequireTimestampAuthorityCertificateListedInTrustedList)
        {
            return ValidationStatus.Failed;
        }

        if (listed && !granted && policy.RequireTimestampAuthorityServiceStatusGranted)
        {
            return ValidationStatus.Failed;
        }

        if (listed && !qualified && policy.RequireQualifiedTimestampServiceType)
        {
            return ValidationStatus.Failed;
        }

        return ValidationStatus.Indeterminate;
    }

    private static string FormatQualificationDescription(bool qualified, bool granted, string? serviceStatus)
    {
        var quality = qualified ? "qualified TSA (QTST)" : "non-qualified TSA";
        var statusBit = granted
            ? "granted"
            : (string.IsNullOrWhiteSpace(serviceStatus) ? "status unknown" : "status not granted");
        return $"{quality}; {statusBit}.";
    }
}
