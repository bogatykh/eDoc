using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using eDocLib;
using eDocLib.Asic.Xades;
using eDocLib.Validation;

namespace eDocLib.Validation.Reporting;

/// <summary>Builds <see cref="DocumentValidationReport"/> and per-signature trees from <see cref="IEdocContainerValidationResult"/> / <see cref="SignatureValidationResult"/>.</summary>
internal static partial class ValidationReportFactory
{
    public static DocumentValidationReport CreateDocumentReport(
        IEdocContainerValidationResult readResult,
        SignatureTrustPolicy policy,
        ValidationReportOptions? reportOptions = null)
    {
        ArgumentNullException.ThrowIfNull(readResult);
        ArgumentNullException.ThrowIfNull(policy);

        var sigReports = new List<SignatureValidationReport>(readResult.Signatures.Count);
        var sigNodes = new List<ValidationResultNode>(readResult.Signatures.Count);
        var reportLocalizer = reportOptions?.ReportLocalizer ?? new DefaultValidationReportLocalizer();
        foreach (var sv in readResult.Signatures)
        {
            var xs = sv.Signature as XadesSignature;
            var report = CreateForSignature(sv.Ordinal, xs, sv.Result, policy, reportOptions, reportLocalizer);
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
            });

        var rootChildren = new List<ValidationResultNode>(1 + readResult.Signatures.Count)
        {
            structure,
        };
        rootChildren.AddRange(sigNodes);

        var root = ValidationResultNode.Branch(
            ValidationType.Root,
            readResult.AllSignaturesValid ? ValidationStatus.Passed : ValidationStatus.Failed,
            rootChildren,
            description: "eDoc container validation");

        return new DocumentValidationReport(readResult.AllSignaturesValid, root, sigReports);
    }

    public static SignatureValidationReport CreateForSignature(
        int ordinal,
        XadesSignature? signature,
        SignatureValidationResult result,
        SignatureTrustPolicy policy,
        ValidationReportOptions? reportOptions = null,
        IValidationReportLocalizer? reportLocalizer = null)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(policy);

        var loc = reportLocalizer ?? reportOptions?.ReportLocalizer ?? new DefaultValidationReportLocalizer();

        var vType = ValidationReportQualifications.GetValidationSignatureType(signature);
        var profile = ValidationReportQualifications.EstimateSignatureProfile(signature);
        var signingCert = signature?.SigningCertificate as X509Certificate2;
        var sigQ = ValidationReportQualifications.EstimateSignatureQualification(result, signingCert);
        var certQ = ValidationReportQualifications.EstimateSignerCertificateQualification(result, signingCert);
        var tsQ = ValidationReportQualifications.EstimateTimestampQualification(policy, result);

        var tree = BuildSignatureSubtree(signature, result, policy, vType, profile, reportOptions, loc);
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

    private static ValidationStatus AggregateStructureStatus(IEdocContainerValidationResult read)
    {
        if (read.Signatures.Count == 0)
        {
            return ValidationStatus.Unchecked;
        }

        return ValidationStatus.Passed;
    }

    private static ValidationResultNode BuildSignatureSubtree(
        XadesSignature? xs,
        SignatureValidationResult result,
        SignatureTrustPolicy policy,
        ValidationSignatureType validationSignatureType,
        SignatureProfile profile,
        ValidationReportOptions? reportOptions,
        IValidationReportLocalizer reportLocalizer)
    {
        var cryptoOk = result.ReferencesAndSignatureValid;
        var id = xs?.Id;

        var typeNode = ValidationResultNode.Leaf(
            ValidationType.SignatureType,
            ValidationStatus.Passed,
            id: id,
            description: reportLocalizer.DescribeValidationSignatureType(validationSignatureType));

        var profileNode = ValidationResultNode.Leaf(
            ValidationType.SignatureProfile,
            ValidationStatus.Passed,
            description: reportLocalizer.DescribeSignatureProfile(profile));

        var methodUri = xs?.SignatureMethod ?? "(unknown)";
        var cryptoSt = CryptoLayerStatus(cryptoOk);
        var cryptoReasons = CryptoValidationReasons(cryptoOk, result.Error);

        var methodNode = ValidationResultNode.Leaf(
            ValidationType.SignatureMethod,
            cryptoSt,
            description: methodUri,
            reasons: cryptoReasons);

        var dataRefs = ValidationResultNode.Leaf(
            ValidationType.SignatureEdocDataObjectReferences,
            cryptoSt,
            reasons: cryptoReasons);

        var sigValue = ValidationResultNode.Leaf(
            ValidationType.SignatureValue,
            cryptoSt,
            reasons: cryptoReasons);

        var signingCertRefs = ValidationResultNode.Leaf(
            ValidationType.SignatureEdocSigningCertificateReferences,
            cryptoSt,
            reasons: cryptoReasons);

        var signerRolesNode = BuildSignerRolesBranch(xs, result, policy);
        var productionPlaceNode = BuildSignatureProductionPlaceBranch(xs);

        var referenceNow = reportOptions?.ReferenceTimeUtc ?? DateTimeOffset.UtcNow;
        var chainNode = BuildCertificateChain(result, policy, referenceNow);
        var revocationNode = BuildRevocationBranch(result, policy);
        var timestampNode = BuildTimestampBranch(signature: xs, result, policy, referenceNow);
        var children = new List<ValidationResultNode>(11)
        {
            typeNode,
            profileNode,
            methodNode,
            dataRefs,
            sigValue,
            signingCertRefs,
            signerRolesNode,
            productionPlaceNode,
            chainNode,
            revocationNode,
            timestampNode,
        };

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
}
