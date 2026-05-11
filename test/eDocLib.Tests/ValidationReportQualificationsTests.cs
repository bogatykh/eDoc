using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
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
            SuggestsQualifiedTimestampService: false,
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
    public void EstimateTimestampQualification_signature_timestamp_imprint_maps_to_Tsa()
    {
        var policy = new SignatureTrustPolicy { TimestampImprintPolicy = SignatureTimestampImprintPolicy.RequireWhenPresent };
        var result = new SignatureValidationResult
        {
            SignatureTimestampImprintValid = true,
        };

        Assert.Equal(TimestampQualification.Tsa, ValidationReportQualifications.EstimateTimestampQualification(policy, result));
    }

    [Fact]
    public void EstimateTimestampQualification_tsa_cms_maps_to_Tsa()
    {
        var policy = new SignatureTrustPolicy { ValidateTsaSigner = true };
        var result = new SignatureValidationResult
        {
            TsaSignerCmsValid = true,
        };

        Assert.Equal(TimestampQualification.Tsa, ValidationReportQualifications.EstimateTimestampQualification(policy, result));
    }

    [Fact]
    public void EstimateTimestampQualification_lists_QTsa_when_policy_enforces_tsa_in_trusted_list_and_validation_succeeds()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=TSL dummy", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var b64 = Convert.ToBase64String(cert.Export(X509ContentType.Cert));
        const string typeA = TslQualificationMapper.ServiceTypeTsaQTST;
        const string status = TslQualificationMapper.ServiceStatusGranted;
        var xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
              <TSPService>
                <ServiceInformation>
                  <ServiceTypeIdentifier>{typeA}</ServiceTypeIdentifier>
                  <ServiceStatus>{status}</ServiceStatus>
                  <ServiceDigitalIdentity>
                    <DigitalId><X509Certificate>{b64}</X509Certificate></DigitalId>
                  </ServiceDigitalIdentity>
                </ServiceInformation>
              </TSPService>
            </TrustServiceStatusList>
            """;
        var index = TrustedListServiceIndex.FromStream(new MemoryStream(Encoding.UTF8.GetBytes(xml)));

        var policy = new SignatureTrustPolicy
        {
            ValidateTsaSigner = true,
            RequireTimestampAuthorityCertificateListedInTrustedList = true,
            RequireTimestampAuthorityServiceStatusGranted = true,
            RequireQualifiedTimestampServiceType = true,
            TrustedListServiceIndex = index,
        };
        var result = new SignatureValidationResult
        {
            Success = true,
            TsaSignerCmsValid = true,
            TimestampAuthorityListedInTrustedList = true,
            TimestampAuthorityTrustedListServiceTypeIdentifiers = new[] { typeA },
            TimestampAuthorityTrustedListServiceStatus = status,
            TimestampAuthorityTrustedListQualificationIndicators = new TslQualificationIndicators(
                SuggestsQualifiedElectronicSignature: false,
                SuggestsQualifiedElectronicSeal: false,
                SuggestsQualifiedTimestampService: true,
                ServiceStatusIsGranted: true),
        };

        Assert.Equal(TimestampQualification.QTsa, ValidationReportQualifications.EstimateTimestampQualification(policy, result));
    }

    [Fact]
    public void EstimateTimestampQualification_stays_Tsa_when_tsl_index_null_even_if_require_flags_set()
    {
        var policy = new SignatureTrustPolicy
        {
            ValidateTsaSigner = true,
            RequireTimestampAuthorityCertificateListedInTrustedList = true,
            RequireTimestampAuthorityServiceStatusGranted = true,
            TrustedListServiceIndex = null,
        };
        var result = new SignatureValidationResult
        {
            Success = true,
            TsaSignerCmsValid = true,
        };

        Assert.Equal(TimestampQualification.Tsa, ValidationReportQualifications.EstimateTimestampQualification(policy, result));
    }

    [Fact]
    public void EstimateSignerCertificateQualification_qc_compliance_both_types_with_sscd_maps_to_QcQscdUnknown()
    {
        using var cert = CreateCertWithQcStatements(
            new QCStatement(new DerObjectIdentifier(SignerCertificateQualificationHeuristics.EtsiQcsQcCompliance)),
            new QCStatement(new DerObjectIdentifier(SignerCertificateQualificationHeuristics.EtsiQcsQcSscd)),
            new QCStatement(new DerObjectIdentifier(SignerCertificateQualificationHeuristics.EtsiQctEsign)),
            new QCStatement(new DerObjectIdentifier(SignerCertificateQualificationHeuristics.EtsiQctEseal)));

        var result = new SignatureValidationResult
        {
            Success = true,
            ReferencesAndSignatureValid = true,
            TrustedListQualificationIndicators = null,
        };

        var q = ValidationReportQualifications.EstimateSignerCertificateQualification(result, cert);
        Assert.Equal(CertificateQualification.QcQscdUnknown, q);
    }
}
