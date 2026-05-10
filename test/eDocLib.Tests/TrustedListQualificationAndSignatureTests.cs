using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using eDocLib.Asic.Container;
using eDocLib.Validation;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

public class TrustedListQualificationAndSignatureTests
{
    [Fact]
    public void TrustedListServiceIndex_merges_ServiceInformation_by_certificate_thumbprint()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=TSL service", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var b64 = Convert.ToBase64String(cert.Export(X509ContentType.Cert));
        const string typeA = "http://uri.etsi.org/TrstSvc/Svctype/QESig/QCertESign";
        const string typeB = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";
        const string status = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted";
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
              <TSPService>
                <ServiceInformation>
                  <ServiceTypeIdentifier>{typeB}</ServiceTypeIdentifier>
                  <ServiceDigitalIdentity>
                    <DigitalId><X509Certificate>{b64}</X509Certificate></DigitalId>
                  </ServiceDigitalIdentity>
                </ServiceInformation>
              </TSPService>
            </TrustServiceStatusList>
            """;
        var index = TrustedListServiceIndex.FromStream(new MemoryStream(Encoding.UTF8.GetBytes(xml)));
        Assert.True(index.TryGetQualification(cert, out var q));
        Assert.Equal(2, q!.ServiceTypeIdentifiers.Count);
        Assert.Contains(typeA, q.ServiceTypeIdentifiers, StringComparer.OrdinalIgnoreCase);
        Assert.Contains(typeB, q.ServiceTypeIdentifiers, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(status, q.ServiceStatusUri);
    }

    [Fact]
    public void TrustedListXmlSignatureVerifier_accepts_enveloped_RSA_SHA256_signature()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=TSL XML signer", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(
            """
            <?xml version="1.0" encoding="UTF-8"?>
            <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
              <TSPService/>
            </TrustServiceStatusList>
            """);

        var signedXml = new SignedXml(doc);
        signedXml.SigningKey = cert.GetRSAPrivateKey();
        var reference = new Reference { Uri = "" };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        signedXml.AddReference(reference);
        var keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(cert));
        signedXml.KeyInfo = keyInfo;
        signedXml.ComputeSignature();
        var sigEl = signedXml.GetXml();
        doc.DocumentElement!.AppendChild(doc.ImportNode(sigEl, deep: true));

        Assert.True(TrustedListXmlSignatureVerifier.TryVerify(doc, out var err), err);
    }

    [Fact]
    public void TrustedListReader_with_signature_verification_builds_index()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=TSL reader test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var b64 = Convert.ToBase64String(cert.Export(X509ContentType.Cert));
        const string typeId = "http://uri.etsi.org/TrstSvc/Svctype/QESig/QCertESign";

        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(
            $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
              <TSPService>
                <ServiceInformation>
                  <ServiceTypeIdentifier>{typeId}</ServiceTypeIdentifier>
                  <ServiceDigitalIdentity>
                    <DigitalId><X509Certificate>{b64}</X509Certificate></DigitalId>
                  </ServiceDigitalIdentity>
                </ServiceInformation>
              </TSPService>
            </TrustServiceStatusList>
            """);

        var signedXml = new SignedXml(doc);
        signedXml.SigningKey = cert.GetRSAPrivateKey();
        var reference = new Reference { Uri = "" };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        signedXml.AddReference(reference);
        var keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(cert));
        signedXml.KeyInfo = keyInfo;
        signedXml.ComputeSignature();
        var sigEl = signedXml.GetXml();
        doc.DocumentElement!.AppendChild(doc.ImportNode(sigEl, deep: true));

        using var ms = new MemoryStream();
        doc.Save(ms);
        ms.Position = 0;

        Assert.True(TrustedListReader.TryLoad(ms, verifyXmlSignature: true, out var index, out var error), error);
        Assert.NotNull(index);
        Assert.True(index!.TryGetQualification(cert, out var q));
        Assert.Contains(typeId, q!.ServiceTypeIdentifiers, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void SignatureValidator_records_TSL_qualification_when_signer_listed()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=eDoc TSL", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var b64 = Convert.ToBase64String(cert.Export(X509ContentType.Cert));
        const string typeId = TslQualificationMapper.ServiceTypeQCertESign;
        var tslXml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
              <TSPService>
                <ServiceInformation>
                  <ServiceTypeIdentifier>{typeId}</ServiceTypeIdentifier>
                  <ServiceStatus>{TslQualificationMapper.ServiceStatusGranted}</ServiceStatus>
                  <ServiceDigitalIdentity>
                    <DigitalId><X509Certificate>{b64}</X509Certificate></DigitalId>
                  </ServiceDigitalIdentity>
                </ServiceInformation>
              </TSPService>
            </TrustServiceStatusList>
            """;
        var index = TrustedListServiceIndex.FromStream(new MemoryStream(Encoding.UTF8.GetBytes(tslXml)));

        var payload = "hello"u8.ToArray();
        var dataFiles = new[] { new DataFile(new MemoryStream(payload), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dataFiles, cert, DateTimeOffset.Parse("2024-06-01T10:00:00Z"));

        var policy = new SignatureTrustPolicy
        {
            ValidateCertificateChain = false,
            TrustedListServiceIndex = index,
        };
        var result = SignatureValidator.Validate(sig, new Dictionary<string, byte[]> { ["doc.txt"] = payload }, policy);
        Assert.True(result.Success, result.Error);
        Assert.True(result.SigningCertificateListedInTrustedList);
        Assert.NotNull(result.TrustedListServiceTypeIdentifiers);
        Assert.Contains(typeId, result.TrustedListServiceTypeIdentifiers!, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(TslQualificationMapper.ServiceStatusGranted, result.TrustedListServiceStatus);
        Assert.NotNull(result.TrustedListQualificationIndicators);
        Assert.True(result.TrustedListQualificationIndicators!.SuggestsQualifiedElectronicSignature);
        Assert.False(result.TrustedListQualificationIndicators.SuggestsQualifiedElectronicSeal);
        Assert.True(result.TrustedListQualificationIndicators.ServiceStatusIsGranted);
    }

    [Fact]
    public void TslQualificationMapper_maps_QCertESeal_and_status()
    {
        var m = TslQualificationMapper.Map(
            new[] { TslQualificationMapper.ServiceTypeQCertESeal },
            TslQualificationMapper.ServiceStatusRecognisedAtNationalLevel);
        Assert.False(m.SuggestsQualifiedElectronicSignature);
        Assert.True(m.SuggestsQualifiedElectronicSeal);
        Assert.True(m.ServiceStatusIsGranted);
    }

    [Fact]
    public void TslQualificationMapper_maps_both_QCertESign_and_QCertESeal_when_listed()
    {
        var m = TslQualificationMapper.Map(
            new[] { TslQualificationMapper.ServiceTypeQCertESign, TslQualificationMapper.ServiceTypeQCertESeal },
            TslQualificationMapper.ServiceStatusGranted);
        Assert.True(m.SuggestsQualifiedElectronicSignature);
        Assert.True(m.SuggestsQualifiedElectronicSeal);
        Assert.True(m.ServiceStatusIsGranted);
    }

    [Fact]
    public void TslQualificationMapper_omitted_service_status_yields_null_granted_flag()
    {
        var m = TslQualificationMapper.Map(new[] { TslQualificationMapper.ServiceTypeQCertESign }, null);
        Assert.True(m.SuggestsQualifiedElectronicSignature);
        Assert.False(m.SuggestsQualifiedElectronicSeal);
        Assert.Null(m.ServiceStatusIsGranted);
    }

    [Fact]
    public void TslQualificationMapper_honours_extra_national_uris()
    {
        const string nationalQes = "http://national.example/trstsvc/qes";
        const string nationalActive = "http://national.example/tsl/service-active";
        var opt = new TslQualificationMappingOptions
        {
            ExtraQualifiedEsignServiceTypeUris = new[] { nationalQes },
            ExtraGrantedLikeServiceStatusUris = new[] { nationalActive },
        };
        var m = TslQualificationMapper.Map(new[] { nationalQes }, nationalActive, opt);
        Assert.True(m.SuggestsQualifiedElectronicSignature);
        Assert.True(m.ServiceStatusIsGranted);
    }

    [Fact]
    public void SignatureValidator_RequireTrustedListServiceStatusGranted_fails_when_status_not_granted_like()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=TSL status", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var b64 = Convert.ToBase64String(cert.Export(X509ContentType.Cert));
        var tslXml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
              <TSPService>
                <ServiceInformation>
                  <ServiceTypeIdentifier>{TslQualificationMapper.ServiceTypeQCertESign}</ServiceTypeIdentifier>
                  <ServiceStatus>http://example.com/unknown-status</ServiceStatus>
                  <ServiceDigitalIdentity>
                    <DigitalId><X509Certificate>{b64}</X509Certificate></DigitalId>
                  </ServiceDigitalIdentity>
                </ServiceInformation>
              </TSPService>
            </TrustServiceStatusList>
            """;
        var index = TrustedListServiceIndex.FromStream(new MemoryStream(Encoding.UTF8.GetBytes(tslXml)));
        var payload = "y"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload), "doc.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2024-06-01T10:00:00Z"));
        var policy = new SignatureTrustPolicy
        {
            ValidateCertificateChain = false,
            TrustedListServiceIndex = index,
            RequireTrustedListServiceStatusGranted = true,
        };
        var result = SignatureValidator.Validate(sig, new Dictionary<string, byte[]> { ["doc.txt"] = payload }, policy);
        Assert.False(result.Success);
        Assert.True(result.SigningCertificateListedInTrustedList);
        Assert.False(result.TrustedListQualificationIndicators!.ServiceStatusIsGranted);
    }

    [Fact]
    public void SignatureValidator_fails_when_require_listed_and_signer_not_in_TSL()
    {
        using var rsaSigner = RSA.Create(2048);
        var reqSigner = new CertificateRequest("CN=signer", rsaSigner, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var signerCert = reqSigner.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        using var rsaOther = RSA.Create(2048);
        var reqOther = new CertificateRequest("CN=other", rsaOther, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var otherCert = reqOther.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var b64 = Convert.ToBase64String(otherCert.Export(X509ContentType.Cert));

        var tslXml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
              <TSPService>
                <ServiceInformation>
                  <ServiceTypeIdentifier>http://example.com/type</ServiceTypeIdentifier>
                  <ServiceDigitalIdentity>
                    <DigitalId><X509Certificate>{b64}</X509Certificate></DigitalId>
                  </ServiceDigitalIdentity>
                </ServiceInformation>
              </TSPService>
            </TrustServiceStatusList>
            """;
        var index = TrustedListServiceIndex.FromStream(new MemoryStream(Encoding.UTF8.GetBytes(tslXml)));

        var payload = "x"u8.ToArray();
        var dataFiles = new[] { new DataFile(new MemoryStream(payload), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dataFiles, signerCert, DateTimeOffset.Parse("2024-06-01T10:00:00Z"));

        var policy = new SignatureTrustPolicy
        {
            ValidateCertificateChain = false,
            TrustedListServiceIndex = index,
            RequireSigningCertificateListedInTrustedList = true,
        };
        var result = SignatureValidator.Validate(sig, new Dictionary<string, byte[]> { ["doc.txt"] = payload }, policy);
        Assert.False(result.Success);
        Assert.False(result.SigningCertificateListedInTrustedList);
    }
}
