using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib.Validation;
using eDocLib.Validation.Reporting;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509.Qualified;
using Xunit;

namespace eDocLib.Tests;

public class ValidationReportQualificationsTests
{
    private static X509Certificate2 CreateCertWithQcStatements(params QCStatement[] statements)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=qc-heuristic", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var der = new DerSequence(statements).GetDerEncoded();
        req.CertificateExtensions.Add(
            new X509Extension(SignerCertificateQualificationHeuristics.QcStatementsExtensionOid, der, critical: false));
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    [Fact]
    public void TryReadEtsiQcStatements_parses_compliance_esign_and_sscd()
    {
        using var cert = CreateCertWithQcStatements(
            new QCStatement(new DerObjectIdentifier(SignerCertificateQualificationHeuristics.EtsiQcsQcCompliance)),
            new QCStatement(new DerObjectIdentifier(SignerCertificateQualificationHeuristics.EtsiQcsQcSscd)),
            new QCStatement(new DerObjectIdentifier(SignerCertificateQualificationHeuristics.EtsiQctEsign)));

        Assert.True(SignerCertificateQualificationHeuristics.TryReadEtsiQcStatements(cert, out var f));
        Assert.True(f.QcCompliance);
        Assert.True(f.QcSscd);
        Assert.True(f.Esign);
        Assert.False(f.Eseal);
    }

    [Fact]
    public void EstimateSignerCertificateQualification_uses_qcStatements_when_no_TSL()
    {
        using var cert = CreateCertWithQcStatements(
            new QCStatement(new DerObjectIdentifier(SignerCertificateQualificationHeuristics.EtsiQcsQcCompliance)),
            new QCStatement(new DerObjectIdentifier(SignerCertificateQualificationHeuristics.EtsiQctEsign)));

        var result = new SignatureValidationResult
        {
            Success = true,
            ReferencesAndSignatureValid = true,
            TrustedListQualificationIndicators = null,
        };

        var q = ValidationReportQualifications.EstimateSignerCertificateQualification(result, cert);
        Assert.Equal(CertificateQualification.QcESig, q);
    }

    [Fact]
    public void EstimateSignerCertificateQualification_eseal_without_compliance_maps_to_ESeal()
    {
        using var cert = CreateCertWithQcStatements(
            new QCStatement(new DerObjectIdentifier(SignerCertificateQualificationHeuristics.EtsiQctEseal)));

        var result = new SignatureValidationResult
        {
            Success = true,
            ReferencesAndSignatureValid = true,
            TrustedListQualificationIndicators = null,
        };

        var q = ValidationReportQualifications.EstimateSignerCertificateQualification(result, cert);
        Assert.Equal(CertificateQualification.ESeal, q);
    }

    [Fact]
    public void EstimateSignatureQualification_eseal_type_yields_ADESeal_without_TSL()
    {
        using var cert = CreateCertWithQcStatements(
            new QCStatement(new DerObjectIdentifier(SignerCertificateQualificationHeuristics.EtsiQctEseal)));

        var result = new SignatureValidationResult
        {
            Success = true,
            ReferencesAndSignatureValid = true,
            TrustedListQualificationIndicators = null,
        };

        var sq = ValidationReportQualifications.EstimateSignatureQualification(result, cert);
        Assert.Equal(SignatureQualification.ADESeal, sq);
    }

    [Fact]
    public void TSL_indicators_take_precedence_over_qcStatements_for_certificate_qualification()
    {
        using var cert = CreateCertWithQcStatements(
            new QCStatement(new DerObjectIdentifier(SignerCertificateQualificationHeuristics.EtsiQctEseal)));

        var tslOnlySign = new TslQualificationIndicators(
            SuggestsQualifiedElectronicSignature: true,
            SuggestsQualifiedElectronicSeal: false,
            ServiceStatusIsGranted: true);

        var result = new SignatureValidationResult
        {
            Success = true,
            ReferencesAndSignatureValid = true,
            TrustedListQualificationIndicators = tslOnlySign,
        };

        var q = ValidationReportQualifications.EstimateSignerCertificateQualification(result, cert);
        Assert.Equal(CertificateQualification.QcESig, q);
    }

    [Fact]
    public void EstimateTimestampQualification_archive_CMS_success_maps_to_Tsa()
    {
        var policy = new SignatureTrustPolicy { ValidateArchiveTimeStampCms = true };
        var result = new SignatureValidationResult
        {
            ArchiveTimeStampCount = 1,
            ArchiveTimeStampsCmsValid = true,
        };

        Assert.Equal(TimestampQualification.Tsa, ValidationReportQualifications.EstimateTimestampQualification(policy, result));
    }

    [Fact]
    public void EstimateTimestampQualification_archive_imprint_only_maps_to_Tsa()
    {
        var policy = new SignatureTrustPolicy { ArchiveTimestampImprintPolicy = ArchiveTimestampImprintPolicy.RequireWhenPresent };
        var result = new SignatureValidationResult
        {
            ArchiveTimeStampCount = 1,
            ArchiveTimeStampImprintsValid = true,
        };

        Assert.Equal(TimestampQualification.Tsa, ValidationReportQualifications.EstimateTimestampQualification(policy, result));
    }
}
