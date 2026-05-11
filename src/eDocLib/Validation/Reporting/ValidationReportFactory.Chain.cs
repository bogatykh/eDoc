using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using eDocLib.Asic.Xades;
using eDocLib.Validation;

namespace eDocLib.Validation.Reporting;

internal static partial class ValidationReportFactory
{
    private static List<ValidationResultNode> BuildChainCertificateNodes(
        IReadOnlyList<CertificateChainDiagnostic> path,
        DateTimeOffset referenceNowUtc)
    {
        var certNodes = new List<ValidationResultNode>(path.Count);
        foreach (var d in path)
        {
            var statuses = d.ElementStatuses;
            List<string>? pkixLines = null;
            var hasPkixElementError = false;
            for (var si = 0; si < statuses.Count; si++)
            {
                var es = statuses[si];
                if (es.Status == X509ChainStatusFlags.NoError)
                {
                    continue;
                }

                hasPkixElementError = true;
                var info = (es.StatusInformation ?? string.Empty).Trim();
                var line = string.IsNullOrEmpty(info) ? es.Status.ToString() : $"{es.Status}: {info}";
                if (line.Length == 0)
                {
                    continue;
                }

                pkixLines ??= new List<string>(statuses.Count);
                pkixLines.Add(line);
            }

            var notBeforeOk = referenceNowUtc >= d.NotBeforeUtc;
            var notAfterOk = referenceNowUtc <= d.NotAfterUtc;
            var notBeforeSt = notBeforeOk ? ValidationStatus.Passed : ValidationStatus.Failed;
            var notAfterSt = notAfterOk ? ValidationStatus.Passed : ValidationStatus.Failed;
            var validityChildren = new[]
            {
                ValidationResultNode.Leaf(
                    ValidationType.SignatureSigningCertificateNotBefore,
                    notBeforeSt,
                    description: d.NotBeforeUtc.ToString("O")),
                ValidationResultNode.Leaf(
                    ValidationType.SignatureSigningCertificateNotAfter,
                    notAfterSt,
                    description: d.NotAfterUtc.ToString("O")),
            };
            var validityBranch = ValidationResultNode.Branch(
                ValidationType.SignatureSigningCertificateValidity,
                AggregateChildren(validityChildren),
                validityChildren);

            var st = hasPkixElementError || !notBeforeOk || !notAfterOk
                ? ValidationStatus.Failed
                : ValidationStatus.Passed;

            var role = ChainPositionLabel(d.Index, path.Count);
            var details = new List<ValidationResultNode>(4)
            {
                ValidationResultNode.Leaf(
                    ValidationType.SignatureSigningCertificateSerial,
                    st,
                    description: d.SerialNumberHex),
                validityBranch,
            };
            if (pkixLines is { Count: > 0 })
            {
                details.Add(
                    ValidationResultNode.Leaf(
                        ValidationType.SignatureSigningCertificatePkixStatuses,
                        ValidationStatus.Failed,
                        description: string.Join("; ", pkixLines)));
            }

            certNodes.Add(
                ValidationResultNode.Branch(
                    ValidationType.SignatureSigningCertificate,
                    st,
                    details,
                    id: d.Thumbprint,
                    description: $"{role}: {d.Subject} ← {d.Issuer}",
                    reasons: Array.Empty<string>()));
        }

        return certNodes;
    }

    private static ValidationResultNode? BuildTsaCertificateChainBranch(
        SignatureValidationResult result,
        DateTimeOffset referenceNowUtc)
    {
        var path = result.TsaSignerCertificateChain;
        if (path is null || path.Count == 0)
        {
            return null;
        }

        var certNodes = BuildChainCertificateNodes(path, referenceNowUtc);
        var agg = result.TsaSignerChainValid switch
        {
            true => ValidationStatus.Passed,
            false => ValidationStatus.Failed,
            _ => AggregateChildren(certNodes),
        };

        return ValidationResultNode.Branch(
            ValidationType.SignatureTimestampCertificateChain,
            agg,
            certNodes,
            description: "TSA certificate PKIX path");
    }

    private static ValidationResultNode BuildCertificateChain(
        SignatureValidationResult result,
        SignatureTrustPolicy policy,
        DateTimeOffset referenceNowUtc)
    {
        if (!policy.ValidateCertificateChain)
        {
            return ValidationResultNode.Branch(
                ValidationType.SignatureSigningCertificateChain,
                ValidationStatus.Unchecked,
                Array.Empty<ValidationResultNode>(),
                description: "PKIX chain validation disabled by policy.");
        }

        var path = result.SignerCertificateChain;
        if (path is null || path.Count == 0)
        {
            var st = result.CertificateChainValid switch
            {
                false => ValidationStatus.Failed,
                _ => ValidationStatus.Unchecked,
            };
            return ValidationResultNode.Branch(
                ValidationType.SignatureSigningCertificateChain,
                st,
                Array.Empty<ValidationResultNode>(),
                description: "No PKIX path diagnostics available.",
                reasons: SingleReason(result.Error));
        }

        var certNodes = BuildChainCertificateNodes(path, referenceNowUtc);

        var agg = result.CertificateChainValid switch
        {
            true => ValidationStatus.Passed,
            false => ValidationStatus.Failed,
            _ => AggregateChildren(certNodes),
        };

        return ValidationResultNode.Branch(
            ValidationType.SignatureSigningCertificateChain,
            agg,
            certNodes);
    }
}
