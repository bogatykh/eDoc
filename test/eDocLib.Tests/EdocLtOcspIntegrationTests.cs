using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using eDocLib;
using eDocLib.Asic.Container;
using eDocLib.Timestamp;
using eDocLib.Validation;
using eDocLib.Validation.Reporting;
using eDocLib.Asic.Xades;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Xunit;

namespace eDocLib.Tests;

/// <summary>EP-13 style: container round-trip + PKIX + <see cref="XadesBesSigner.AppendUnsignedRevocationValues"/>.</summary>
public class EdocLtOcspIntegrationTests
{
    [Fact]
    public void OpenAndValidate_succeeds_with_embedded_crl_only_under_custom_anchor()
    {
        var (issuer, leaf, crlDer) = CreateIssuerLeafAndEmptyCrl("CA CRL edoc", "Signer CRL edoc");
        using (issuer)
        using (leaf)
        {
            var payload = "edoc-lt-crl"u8.ToArray();
            var sig = XadesBesSigner.Sign(
                new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
                leaf,
                DateTimeOffset.Parse("2025-09-01T09:00:00Z"));
            XadesBesSigner.AppendUnsignedRevocationValues(sig, ocspResponseDer: null, crlDer: [crlDer]);

            var edoc = Edoc.CreateNew();
            edoc.AddDataObject(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
            edoc.AddSignature(sig);

            using var zip = new MemoryStream();
            edoc.Save(zip);
            zip.Position = 0;

            var policy = new SignatureTrustPolicy
            {
                ValidateCertificateChain = true,
                RevocationMode = X509RevocationMode.NoCheck,
                CustomTrustAnchors = new X509Certificate2Collection(issuer),
                VerifyUnsignedRevocationWhenPresent = true,
            };

            var read = EdocValidation.OpenAndValidate(zip, policy);
            Assert.True(read.AllSignaturesValid, read.Signatures.ElementAtOrDefault(0)?.Result.Error);
            Assert.True(read.Signatures[0].Result.Success);
            Assert.True(read.Signatures[0].Result.UnsignedRevocationArtifactsValid);
        }
    }

    [Fact]
    public void EdocLongTermSigningJob_round_trip_validates_with_embedded_crl_only()
    {
        var (issuer, leaf, crlDer) = CreateIssuerLeafAndEmptyCrl("CA LT job CRL", "Signer LT job CRL");
        using (issuer)
        using (leaf)
        {
            var payload = "edoc-lt-job-crl"u8.ToArray();
            var edoc = Edoc.CreateNew();
            edoc.AddDataObject(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
            var job = new EdocLongTermSigningJob(edoc, leaf, DateTimeOffset.Parse("2025-09-02T09:00:00Z"))
            {
                CaCertificatesToEmbed = new[] { issuer },
                CrlDerBlobs = new[] { crlDer },
            };
            var prep = job.Prepare();
            var sigBytes = leaf.GetRSAPrivateKey()!.SignData(
                prep.GetSignableBytes(),
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            job.CompleteWithEmbeddedMaterial(prep, sigBytes);

            using var zip = new MemoryStream();
            edoc.Save(zip);
            zip.Position = 0;

            var policy = new SignatureTrustPolicy
            {
                ValidateCertificateChain = true,
                RevocationMode = X509RevocationMode.NoCheck,
                CustomTrustAnchors = new X509Certificate2Collection(issuer),
                VerifyUnsignedRevocationWhenPresent = true,
            };

            var read = EdocValidation.OpenAndValidate(zip, policy);
            Assert.True(read.AllSignaturesValid);
            Assert.True(read.Signatures[0].Result.UnsignedRevocationArtifactsValid);
        }
    }

    [Fact]
    public void OpenAndValidate_succeeds_with_embedded_ocsp_under_custom_anchor()
    {
        var (issuer, leaf, ocspDer) = CreateIssuerLeafAndIssuerSignedOcsp("CA OCSP edoc", "Signer OCSP edoc");
        using (issuer)
        using (leaf)
        {
            var payload = "edoc-lt-ocsp"u8.ToArray();
            var sig = XadesBesSigner.Sign(
                new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
                leaf,
                DateTimeOffset.Parse("2025-08-01T09:00:00Z"));
            XadesBesSigner.AppendUnsignedRevocationValues(sig, [ocspDer], null);

            var edoc = Edoc.CreateNew();
            edoc.AddDataObject(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
            edoc.AddSignature(sig);

            using var zip = new MemoryStream();
            edoc.Save(zip);
            zip.Position = 0;

            var policy = new SignatureTrustPolicy
            {
                ValidateCertificateChain = true,
                RevocationMode = X509RevocationMode.NoCheck,
                CustomTrustAnchors = new X509Certificate2Collection(issuer),
                VerifyUnsignedRevocationWhenPresent = true,
                StrictEmbeddedOcspValidateResponderCertificateChain = true,
            };

            var read = EdocValidation.OpenAndValidate(zip, policy);
            Assert.True(read.AllSignaturesValid);
            Assert.True(read.Signatures[0].Result.Success);
            Assert.True(read.Signatures[0].Result.UnsignedRevocationArtifactsValid);
        }
    }

    [Fact]
    public void EdocLongTermSigningJob_round_trip_validates_with_embedded_ocsp_and_strict_responder_pkix()
    {
        var (issuer, leaf, ocspDer) = CreateIssuerLeafAndIssuerSignedOcsp("CA LT job OCSP", "Signer LT job OCSP");
        using (issuer)
        using (leaf)
        {
            var payload = "edoc-lt-job-ocsp"u8.ToArray();
            var edoc = Edoc.CreateNew();
            edoc.AddDataObject(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
            var job = new EdocLongTermSigningJob(edoc, leaf, DateTimeOffset.Parse("2025-08-02T09:00:00Z"))
            {
                CaCertificatesToEmbed = new[] { issuer },
                OcspDerBlobs = new[] { ocspDer },
            };
            var prep = job.Prepare();
            var sigBytes = leaf.GetRSAPrivateKey()!.SignData(
                prep.GetSignableBytes(),
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            job.CompleteWithEmbeddedMaterial(prep, sigBytes);

            using var zip = new MemoryStream();
            edoc.Save(zip);
            zip.Position = 0;

            var policy = new SignatureTrustPolicy
            {
                ValidateCertificateChain = true,
                RevocationMode = X509RevocationMode.NoCheck,
                CustomTrustAnchors = new X509Certificate2Collection(issuer),
                VerifyUnsignedRevocationWhenPresent = true,
                StrictEmbeddedOcspValidateResponderCertificateChain = true,
            };

            var read = EdocValidation.OpenAndValidate(zip, policy);
            Assert.True(read.AllSignaturesValid);
            Assert.True(read.Signatures[0].Result.UnsignedRevocationArtifactsValid);
        }
    }

    /// <summary>
    /// Same LT job + OCSP path as <see cref="EdocLongTermSigningJob_round_trip_validates_with_embedded_ocsp_and_strict_responder_pkix"/>,
    /// plus document-level <see cref="EdocValidation.BuildValidationReport"/> (same reporting expectations as <see cref="LtFixtureOpenAndValidateTests"/>).
    /// </summary>
    [Fact]
    public void EdocLongTermSigningJob_BuildValidationReport_embedded_ocsp_shows_qualified_profile_and_revocation_passed()
    {
        var (issuer, leaf, ocspDer) = CreateIssuerLeafAndIssuerSignedOcsp("CA LT report", "Signer LT report");
        using (issuer)
        using (leaf)
        {
            var payload = "edoc-lt-job-ocsp-report"u8.ToArray();
            var edoc = Edoc.CreateNew();
            edoc.AddDataObject(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
            var job = new EdocLongTermSigningJob(edoc, leaf, DateTimeOffset.Parse("2025-08-04T09:00:00Z"))
            {
                CaCertificatesToEmbed = new[] { issuer },
                OcspDerBlobs = new[] { ocspDer },
            };
            var prep = job.Prepare();
            var sigBytes = leaf.GetRSAPrivateKey()!.SignData(
                prep.GetSignableBytes(),
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            job.CompleteWithEmbeddedMaterial(prep, sigBytes);

            using var zip = new MemoryStream();
            edoc.Save(zip);
            zip.Position = 0;

            var policy = new SignatureTrustPolicy
            {
                ValidateCertificateChain = true,
                RevocationMode = X509RevocationMode.NoCheck,
                CustomTrustAnchors = new X509Certificate2Collection(issuer),
                VerifyUnsignedRevocationWhenPresent = true,
                StrictEmbeddedOcspValidateResponderCertificateChain = true,
            };

            var read = EdocValidation.OpenAndValidate(zip, policy);
            Assert.True(read.AllSignaturesValid);

            var report = read.BuildValidationReport(policy);
            Assert.True(report.AllSignaturesValid);
            var sigReport = Assert.Single(report.Signatures);
            Assert.Equal(SignatureProfile.QualifiedSignature, sigReport.SignatureProfile);
            Assert.Equal(SignatureValidationIndication.TotalPassed, sigReport.Indication);

            var rev = Assert.Single(sigReport.Tree.Children, n => n.Type == ValidationType.SignatureRevocation);
            Assert.Equal(ValidationStatus.Passed, rev.Status);
            Assert.Contains(
                rev.Children,
                c => c.Type == ValidationType.SignatureRevocationEmbeddedUnsigned && c.Status == ValidationStatus.Passed);
        }
    }

    /// <summary>
    /// EP-13 + V-05: same LT container as embedded-OCSP report test, plus <see cref="SignatureTrustPolicy.TrustedListServiceIndex"/> so qualification resolves to QES on validate (host supplies LT material; no automatic TSL-driven signing helper).
    /// </summary>
    [Fact]
    public void EdocLongTermSigningJob_LT_embedded_ocsp_TrustedListServiceIndex_maps_QES_on_validate()
    {
        var (issuer, leaf, ocspDer) = CreateIssuerLeafAndIssuerSignedOcsp("CA LT TSL", "Signer LT TSL");
        using (issuer)
        using (leaf)
        {
            var payload = "edoc-lt-tsl-qes"u8.ToArray();
            var edoc = Edoc.CreateNew();
            edoc.AddDataObject(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
            var job = new EdocLongTermSigningJob(edoc, leaf, DateTimeOffset.Parse("2025-08-05T09:00:00Z"))
            {
                CaCertificatesToEmbed = new[] { issuer },
                OcspDerBlobs = new[] { ocspDer },
            };
            var prep = job.Prepare();
            var sigBytes = leaf.GetRSAPrivateKey()!.SignData(
                prep.GetSignableBytes(),
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            job.CompleteWithEmbeddedMaterial(prep, sigBytes);

            using var zip = new MemoryStream();
            edoc.Save(zip);
            zip.Position = 0;

            var leafB64 = Convert.ToBase64String(leaf.Export(X509ContentType.Cert));
            var tslXml =
                $"""
                <?xml version="1.0" encoding="UTF-8"?>
                <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
                  <TSPService>
                    <ServiceInformation>
                      <ServiceTypeIdentifier>{TslQualificationMapper.ServiceTypeQCertESign}</ServiceTypeIdentifier>
                      <ServiceStatus>{TslQualificationMapper.ServiceStatusGranted}</ServiceStatus>
                      <ServiceDigitalIdentity>
                        <DigitalId><X509Certificate>{leafB64}</X509Certificate></DigitalId>
                      </ServiceDigitalIdentity>
                    </ServiceInformation>
                  </TSPService>
                </TrustServiceStatusList>
                """;
            var index = TrustedListServiceIndex.FromStream(new MemoryStream(Encoding.UTF8.GetBytes(tslXml)));

            var policy = new SignatureTrustPolicy
            {
                ValidateCertificateChain = true,
                RevocationMode = X509RevocationMode.NoCheck,
                CustomTrustAnchors = new X509Certificate2Collection(issuer),
                VerifyUnsignedRevocationWhenPresent = true,
                StrictEmbeddedOcspValidateResponderCertificateChain = true,
                TrustedListServiceIndex = index,
            };

            var read = EdocValidation.OpenAndValidate(zip, policy);
            Assert.True(read.AllSignaturesValid, read.Signatures[0].Result.Error);
            var vr = read.Signatures[0].Result;
            Assert.True(vr.SigningCertificateListedInTrustedList);
            Assert.NotNull(vr.TrustedListQualificationIndicators);
            Assert.True(vr.TrustedListQualificationIndicators!.SuggestsQualifiedElectronicSignature);

            var report = read.BuildValidationReport(policy);
            var sigReport = Assert.Single(report.Signatures);
            Assert.Equal(SignatureProfile.QualifiedSignature, sigReport.SignatureProfile);
            Assert.Equal(SignatureQualification.QESig, sigReport.SignatureQualification);
            Assert.Equal(SignatureValidationIndication.TotalPassed, sigReport.Indication);
        }
    }

    [Fact]
    public async Task EdocLongTermSigningJob_with_timestamp_round_trip_validates_ocsp_imprint_and_strict_responder_pkix()
    {
        var (issuer, leaf, ocspDer) = CreateIssuerLeafAndIssuerSignedOcsp("CA LT TST", "Signer LT TST");
        using (issuer)
        using (leaf)
        {
            var payload = "edoc-lt-tst-ocsp"u8.ToArray();
            var edoc = Edoc.CreateNew();
            edoc.AddDataObject(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
            var tsp = new LocalSha256Rfc3161TimestampProvider();
            var job = new EdocLongTermSigningJob(edoc, leaf, DateTimeOffset.Parse("2025-08-03T09:00:00Z"))
            {
                CaCertificatesToEmbed = new[] { issuer },
                OcspDerBlobs = new[] { ocspDer },
            };
            var prep = job.Prepare();
            var sigBytes = leaf.GetRSAPrivateKey()!.SignData(
                prep.GetSignableBytes(),
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            await job.CompleteWithEmbeddedMaterialAndTimestampAsync(prep, sigBytes, tsp);

            using var zip = new MemoryStream();
            edoc.Save(zip);
            zip.Position = 0;

            using var tsaAnchor = LocalSha256Rfc3161TimestampProvider.EmbeddedTsaCertificate;
            var policy = new SignatureTrustPolicy
            {
                ValidateCertificateChain = true,
                RevocationMode = X509RevocationMode.NoCheck,
                CustomTrustAnchors = new X509Certificate2Collection(issuer),
                VerifyUnsignedRevocationWhenPresent = true,
                StrictEmbeddedOcspValidateResponderCertificateChain = true,
                TimestampImprintPolicy = SignatureTimestampImprintPolicy.RequireWhenPresent,
                ValidateTsaSigner = true,
                ValidateTsaSignerChain = true,
                TsaTrustAnchors = new X509Certificate2Collection(tsaAnchor),
            };

            var read = EdocValidation.OpenAndValidate(zip, policy);
            Assert.True(read.AllSignaturesValid);
            Assert.True(read.Signatures[0].Result.SignatureTimestampImprintValid);
            Assert.True(read.Signatures[0].Result.TsaSignerCmsValid);
            Assert.True(read.Signatures[0].Result.TsaSignerChainValid);
            Assert.True(read.Signatures[0].Result.UnsignedRevocationArtifactsValid);
        }
    }

    /// <summary>CA + EE leaf with private key; OCSP good response signed by CA with embedded CA cert.</summary>
    private static (X509Certificate2 Issuer, X509Certificate2 Leaf, byte[] OcspDer) CreateIssuerLeafAndIssuerSignedOcsp(
        string issuerCn,
        string leafCn)
    {
        using var issuerRsa = RSA.Create(2048);
        var issuerReq = new CertificateRequest(
            "CN=" + issuerCn,
            issuerRsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        issuerReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        issuerReq.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, false));
        var issuer = issuerReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddYears(5));

        using var leafRsa = RSA.Create(2048);
        var leafReq = new CertificateRequest(
            "CN=" + leafCn,
            leafRsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        var leafSerial = new byte[8];
        RandomNumberGenerator.Fill(leafSerial);
        var leafPub = leafReq.Create(issuer, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), leafSerial);
        var leaf = leafPub.CopyWithPrivateKey(leafRsa);

        var parser = new X509CertificateParser();
        var issuerBc = parser.ReadCertificate(issuer.RawData);
        var leafBc = parser.ReadCertificate(leaf.RawData);
        var issuerKeyPair = DotNetUtilities.GetKeyPair(issuer.GetRSAPrivateKey()!);

#pragma warning disable CS0618
        var certId = new CertificateID(OiwObjectIdentifiers.IdSha1.Id, issuerBc, leafBc.SerialNumber);
#pragma warning restore CS0618
        var basicGen = new BasicOcspRespGenerator(issuerKeyPair.Public);
        basicGen.AddResponse(certId, null, DateTime.UtcNow, null, null);
        var basic = basicGen.Generate(
            new Asn1SignatureFactory("SHA256WithRSA", issuerKeyPair.Private),
            [issuerBc],
            DateTime.UtcNow);
        var ocspDer = new OCSPRespGenerator().Generate(OcspRespStatus.Successful, basic).GetEncoded();

        return (issuer, leaf, ocspDer);
    }

    /// <summary>CA + EE leaf; empty CRL (issuer-signed) covering the leaf serial — EP-13 CRL path.</summary>
    private static (X509Certificate2 Issuer, X509Certificate2 Leaf, byte[] CrlDer) CreateIssuerLeafAndEmptyCrl(
        string issuerCn,
        string leafCn)
    {
        using var issuerRsa = RSA.Create(2048);
        var issuerReq = new CertificateRequest(
            "CN=" + issuerCn,
            issuerRsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        issuerReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        issuerReq.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, false));
        var issuer = issuerReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddYears(5));

        using var leafRsa = RSA.Create(2048);
        var leafReq = new CertificateRequest(
            "CN=" + leafCn,
            leafRsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        var leafSerial = new byte[8];
        RandomNumberGenerator.Fill(leafSerial);
        var leafPub = leafReq.Create(issuer, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), leafSerial);
        var leaf = leafPub.CopyWithPrivateKey(leafRsa);

        var parser = new X509CertificateParser();
        var issuerBc = parser.ReadCertificate(issuer.RawData);
        var issuerKeyPair = DotNetUtilities.GetKeyPair(issuer.GetRSAPrivateKey()!);

        var crlGen = new X509V2CrlGenerator();
        crlGen.SetIssuerDN(issuerBc.SubjectDN);
        crlGen.SetThisUpdate(DateTime.UtcNow.AddHours(-2));
        crlGen.SetNextUpdate(DateTime.UtcNow.AddDays(30));
        var crl = crlGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", issuerKeyPair.Private));
        var crlDer = crl.GetEncoded();

        return (issuer, leaf, crlDer);
    }
}
