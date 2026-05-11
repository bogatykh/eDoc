using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using eDocLib;
using eDocLib.Revocation;
using eDocLib.Validation;
using eDocLib.Asic.Xades;

namespace eDocLib.Validation.Reporting;

/// <summary>Builds <see cref="DocumentValidationReport"/> and per-signature trees from <see cref="IEdocContainerValidationResult"/> / <see cref="SignatureValidationResult"/>.</summary>
internal static class ValidationReportFactory
{
    /// <summary>Creates document report.</summary>
    public static DocumentValidationReport CreateDocumentReport(
        IEdocContainerValidationResult readResult,
        SignatureTrustPolicy policy,
        ValidationReportOptions? reportOptions = null)
    {
        ArgumentNullException.ThrowIfNull(readResult);
        ArgumentNullException.ThrowIfNull(policy);

        var sigReports = new List<SignatureValidationReport>(readResult.Signatures.Count);
        var sigNodes = new List<ValidationResultNode>(readResult.Signatures.Count);
        foreach (var sv in readResult.Signatures)
        {
            var xs = sv.Signature as XadesSignature;
            var report = CreateForSignature(sv.Ordinal, xs, sv.Result, policy, reportOptions);
            sigReports.Add(report);
            sigNodes.Add(report.Tree);
        }

        var structure = ValidationResultNode.Branch(
            ValidationType.Structure,
            AggregateStructureStatus(readResult),
            new[]
            {
                ValidationResultNode.Leaf(
                    ValidationType.StructureSignatureCount,
                    ValidationStatus.Passed,
                    description: readResult.Signatures.Count.ToString()),
                ValidationResultNode.Leaf(
                    ValidationType.StructureEdocDataObjectCount,
                    ValidationStatus.Passed,
                    description: readResult.Edoc.DataFiles.Count.ToString()),
                ValidationResultNode.Leaf(
                    ValidationType.StructurePdfPageCount,
                    ValidationStatus.Unchecked,
                    description: "Not applicable (ASiC-E / XML)."),
            });

        var rootChildren = new List<ValidationResultNode> { structure };
        rootChildren.AddRange(sigNodes);

        var root = ValidationResultNode.Branch(
            ValidationType.Root,
            readResult.AllSignaturesValid ? ValidationStatus.Passed : ValidationStatus.Failed,
            rootChildren,
            description: "eDoc container validation");

        return new DocumentValidationReport(readResult.AllSignaturesValid, root, sigReports);
    }

    /// <summary>Creates for signature.</summary>
    public static SignatureValidationReport CreateForSignature(
        int ordinal,
        XadesSignature? signature,
        SignatureValidationResult result,
        SignatureTrustPolicy policy,
        ValidationReportOptions? reportOptions = null)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(policy);

        var vType = ValidationReportQualifications.GetValidationSignatureType(signature);
        var profile = ValidationReportQualifications.EstimateSignatureProfile(signature);
        var signingCert = signature?.SigningCertificate as X509Certificate2;
        var sigQ = ValidationReportQualifications.EstimateSignatureQualification(result, signingCert);
        var certQ = ValidationReportQualifications.EstimateSignerCertificateQualification(result, signingCert);
        var tsQ = ValidationReportQualifications.EstimateTimestampQualification(policy, result);

        var tree = BuildSignatureSubtree(signature, result, policy, vType, profile, reportOptions);
        var paths = SignatureCertificatePathSummary.FromSignatureValidationResult(result);
        return new SignatureValidationReport(
            ordinal,
            vType,
            profile,
            sigQ,
            certQ,
            tsQ,
            result.GetIndication(),
            tree,
            result,
            paths);
    }

    /// <summary>Aggregates structure status.</summary>
    private static ValidationStatus AggregateStructureStatus(IEdocContainerValidationResult read)
    {
        if (read.Signatures.Count == 0)
        {
            return ValidationStatus.Unchecked;
        }

        return ValidationStatus.Passed;
    }

    /// <summary>Builds signature subtree.</summary>
    private static ValidationResultNode BuildSignatureSubtree(
        XadesSignature? xs,
        SignatureValidationResult result,
        SignatureTrustPolicy policy,
        ValidationSignatureType validationSignatureType,
        SignatureProfile profile,
        ValidationReportOptions? reportOptions)
    {
        var cryptoOk = result.ReferencesAndSignatureValid;
        var id = xs?.Id;

        var typeNode = ValidationResultNode.Leaf(
            ValidationType.SignatureType,
            ValidationStatus.Passed,
            id: id,
            description: validationSignatureType.ToString());

        var profileNode = ValidationResultNode.Leaf(
            ValidationType.SignatureProfile,
            ValidationStatus.Passed,
            description: profile.ToString());

        var methodUri = xs?.SignatureMethod ?? "(unknown)";
        var methodNode = ValidationResultNode.Leaf(
            ValidationType.SignatureMethod,
            cryptoOk ? ValidationStatus.Passed : ValidationStatus.Failed,
            description: methodUri,
            reasons: cryptoOk ? Array.Empty<string>() : SingleReason(result.Error));

        var dataRefs = ValidationResultNode.Leaf(
            ValidationType.SignatureEdocDataObjectReferences,
            cryptoOk ? ValidationStatus.Passed : ValidationStatus.Failed,
            reasons: cryptoOk ? Array.Empty<string>() : SingleReason(result.Error));

        var sigValue = ValidationResultNode.Leaf(
            ValidationType.SignatureValue,
            cryptoOk ? ValidationStatus.Passed : ValidationStatus.Failed,
            reasons: cryptoOk ? Array.Empty<string>() : SingleReason(result.Error));

        var signingCertRefs = ValidationResultNode.Leaf(
            ValidationType.SignatureEdocSigningCertificateReferences,
            cryptoOk ? ValidationStatus.Passed : ValidationStatus.Failed,
            reasons: cryptoOk ? Array.Empty<string>() : SingleReason(result.Error));

        var pdfAdobe = ValidationResultNode.Leaf(
            ValidationType.SignaturePdfAdobePkcs7DetachedSignedAttributes,
            ValidationStatus.Unchecked,
            description: "Not applicable (XML eDoc).");

        var pdfEtsi = ValidationResultNode.Leaf(
            ValidationType.SignaturePdfEtsiCadesDetachedSignedAttributes,
            ValidationStatus.Unchecked,
            description: "Not applicable (XML eDoc).");

        var signerRolesNode = BuildSignerRolesBranch(xs, result, policy);
        var productionPlaceNode = BuildSignatureProductionPlaceBranch(xs);

        var referenceNow = reportOptions?.ReferenceTimeUtc ?? DateTimeOffset.UtcNow;
        var chainNode = BuildCertificateChain(result, policy, referenceNow);
        var revocationNode = BuildRevocationBranch(result, policy);
        var timestampNode = BuildTimestampBranch(signature: xs, result, policy, referenceNow);
        var archiveTsNode = TryBuildArchiveTimestampBranch(signature: xs, result, policy);

        var children = new List<ValidationResultNode>
        {
            typeNode,
            profileNode,
            methodNode,
            dataRefs,
            sigValue,
            signingCertRefs,
            pdfAdobe,
            pdfEtsi,
            signerRolesNode,
            productionPlaceNode,
            chainNode,
            revocationNode,
            timestampNode,
        };
        if (archiveTsNode is not null)
        {
            children.Add(archiveTsNode);
        }

        var sigStatus = result.GetIndication() switch
        {
            SignatureValidationIndication.TotalPassed => ValidationStatus.Passed,
            SignatureValidationIndication.TotalFailed => ValidationStatus.Failed,
            _ => ValidationStatus.Indeterminate,
        };

        return ValidationResultNode.Branch(
            ValidationType.Signature,
            sigStatus,
            children,
            id: id,
            description: "XML-DSig / XAdES signature");
    }

    /// <summary>Builds chain certificate nodes.</summary>
    private static List<ValidationResultNode> BuildChainCertificateNodes(
        IReadOnlyList<CertificateChainDiagnostic> path,
        DateTimeOffset referenceNowUtc)
    {
        var certNodes = new List<ValidationResultNode>(path.Count);
        foreach (var d in path)
        {
            var flags = d.ElementStatuses.Where(s => s.Status != X509ChainStatusFlags.NoError).ToArray();
            var statusTexts = flags
                .Select(f =>
                {
                    var info = (f.StatusInformation ?? string.Empty).Trim();
                    return string.IsNullOrEmpty(info) ? f.Status.ToString() : $"{f.Status}: {info}";
                })
                .Where(s => s.Length > 0)
                .ToArray();
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

            var st = flags.Length > 0 || !notBeforeOk || !notAfterOk
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
            if (statusTexts.Length > 0)
            {
                details.Add(
                    ValidationResultNode.Leaf(
                        ValidationType.SignatureSigningCertificatePkixStatuses,
                        ValidationStatus.Failed,
                        description: string.Join("; ", statusTexts)));
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

    /// <summary>Builds TSA certificate chain branch.</summary>
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

    /// <summary>Builds certificate chain.</summary>
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

    /// <summary>Builds revocation branch.</summary>
    private static ValidationResultNode BuildRevocationBranch(SignatureValidationResult result, SignatureTrustPolicy policy)
    {
        var r = result.Revocation;
        var parts = new List<string>();
        var children = new List<ValidationResultNode>(3);

        // PKIX / chain revocation mode
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

        // Embedded unsigned RevocationValues
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

        // Application-controlled online revocation
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

    /// <summary>
    /// Renders one revocation source as either a leaf (when no per-artifact outcomes are available) or a branch
    /// with one leaf per <see cref="RevocationArtifactOutcome"/>.
    /// </summary>
    private static ValidationResultNode BuildRevocationArtifactNode(
        ValidationType branchType,
        ValidationType artifactType,
        ValidationStatus status,
        string description,
        IReadOnlyList<RevocationArtifactOutcome>? outcomes)
    {
        if (outcomes is { Count: > 0 })
        {
            var artifactChildren = outcomes
                .Select(o => ValidationResultNode.Leaf(
                    artifactType,
                    o.Success ? ValidationStatus.Passed : ValidationStatus.Failed,
                    description: DescribeRevocationArtifactOutcome(o)))
                .ToArray();
            return ValidationResultNode.Branch(branchType, status, artifactChildren, description: description);
        }

        return ValidationResultNode.Leaf(branchType, status, description: description);
    }

    /// <summary>Describes revocation artifact outcome.</summary>
    private static string DescribeRevocationArtifactOutcome(RevocationArtifactOutcome o)
    {
        var label = o.Kind == RevocationArtifactKind.Ocsp ? "OCSP" : "CRL";
        return o.Success
            ? $"{label} #{o.Ordinal}: OK"
            : $"{label} #{o.Ordinal}: {o.Detail ?? "Failed"}";
    }

    /// <summary>Aggregates revocation branch status.</summary>
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

    /// <summary>Describes tri.</summary>
    private static string DescribeTri(bool? value, string label) =>
        value switch
        {
            true => $"{label}: passed.",
            false => $"{label}: failed.",
            _ => $"{label}: not applicable or not run.",
        };

    /// <summary>Describes nullable bool.</summary>
    private static string DescribeNullableBool(bool? value) =>
        value switch { true => "true", false => "false", _ => "null" };

    /// <summary>Builds timestamp branch.</summary>
    private static ValidationResultNode BuildTimestampBranch(
        XadesSignature? signature,
        SignatureValidationResult result,
        SignatureTrustPolicy policy,
        DateTimeOffset referenceNowUtc)
    {
        var hasTs = signature is not null
            && SignatureTimestampVerifier.ContainsEmbeddedSignatureTimestamp(signature.GetSignatureOwnerDocument());

        var children = new List<ValidationResultNode>();

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
                        reasons: SingleReason(result.Error)));
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
                        reasons: SingleReason(result.Error)));
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
                            reasons: SingleReason(result.Error)));
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

    /// <summary>Attempts to build archive timestamp branch.</summary>
    private static ValidationResultNode? TryBuildArchiveTimestampBranch(
        XadesSignature? signature,
        SignatureValidationResult result,
        SignatureTrustPolicy policy)
    {
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
                    reasons: SingleReason(result.Error)),
            };

            return ValidationResultNode.Branch(
                ValidationType.SignatureArchiveTimeStamp,
                AggregateChildren(cmsOffImprintOn),
                cmsOffImprintOn);
        }

        var children = new List<ValidationResultNode>();
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
                    reasons: SingleReason(result.Error)));
            if (policy.ValidateArchiveTimeStampChain)
            {
                children.Add(
                    ValidationResultNode.Leaf(
                        ValidationType.SignatureArchiveTimeStampCertificate,
                        Tri(result.ArchiveTimeStampsChainValid),
                        reasons: SingleReason(result.Error)));
            }

            if (policy.ArchiveTimestampImprintPolicy == ArchiveTimestampImprintPolicy.RequireWhenPresent)
            {
                children.Add(
                    ValidationResultNode.Leaf(
                        ValidationType.SignatureArchiveTimeStampImprint,
                        Tri(result.ArchiveTimeStampImprintsValid),
                        reasons: SingleReason(result.Error)));
            }
        }

        return children.Count == 1
            ? children[0]
            : ValidationResultNode.Branch(
                ValidationType.SignatureArchiveTimeStamp,
                AggregateChildren(children),
                children);
    }

    /// <summary>Maps a nullable boolean to a validation status.</summary>
    private static ValidationStatus Tri(bool? value) =>
        value switch
        {
            true => ValidationStatus.Passed,
            false => ValidationStatus.Failed,
            _ => ValidationStatus.Unchecked,
        };

    /// <summary>Builds signer roles branch.</summary>
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

        var roleTexts = new List<string>();
        if (signature is not null)
        {
            foreach (var r in signature.SignerRoles)
            {
                roleTexts.Add(string.IsNullOrWhiteSpace(r) ? "(empty)" : r.Trim());
            }
        }

        var desc = roleTexts.Count == 0
            ? "No non-empty ClaimedRole text."
            : "Roles: " + string.Join(", ", roleTexts);

        return ValidationResultNode.Leaf(
            ValidationType.SignatureSignerClaimedRoles,
            status,
            description: desc,
            reasons: status == ValidationStatus.Failed ? SingleReason(result.Error) : Array.Empty<string>());
    }

    /// <summary>Builds signature production place branch.</summary>
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

        var parts = new List<string>();
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

    /// <summary>Returns the display label for a chain position.</summary>
    private static string ChainPositionLabel(int index, int chainLength)
    {
        if (chainLength <= 0)
        {
            return "Certificate";
        }

        if (index == 0)
        {
            return "End entity";
        }

        if (index == chainLength - 1)
        {
            return "Trust anchor";
        }

        return "Intermediate";
    }

    /// <summary>Aggregates children.</summary>
    private static ValidationStatus AggregateChildren(IReadOnlyList<ValidationResultNode> nodes)
    {
        if (nodes.Any(n => n.Status == ValidationStatus.Failed))
        {
            return ValidationStatus.Failed;
        }

        if (nodes.Any(n => n.Status == ValidationStatus.Indeterminate))
        {
            return ValidationStatus.Indeterminate;
        }

        if (nodes.Any(n => n.Status == ValidationStatus.Passed))
        {
            return ValidationStatus.Passed;
        }

        return ValidationStatus.Unchecked;
    }

    /// <summary>Returns a single validation reason.</summary>
    private static IReadOnlyList<string> SingleReason(string? error) =>
        string.IsNullOrWhiteSpace(error) ? Array.Empty<string>() : new[] { error.Trim() };
}
