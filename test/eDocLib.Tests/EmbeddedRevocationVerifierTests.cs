using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib.Asic.Container;
using eDocLib.Revocation;
using eDocLib.Revocation.Verify;
using eDocLib.Validation;
using eDocLib.Asic.Xades;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Xunit;

namespace eDocLib;

public class EmbeddedRevocationVerifierTests
{
    [Fact]
    public async Task TryVerifyUnsignedArtifacts_accepts_good_ocsp_against_chain()
    {
        var (ocspDer, leafPub, issuerPub) =
            BcOcspRevocationTestData.BuildGoodOcspWithIssuerResponderEmbedded(BigInteger.ValueOf(42_001));
        var chain = new[] { leafPub, issuerPub };
        Assert.True(
            EmbeddedRevocationVerifier.TryVerifyUnsignedArtifacts(leafPub, [ocspDer], [], chain, out var err),
            err);
    }

    [Fact]
    public async Task TryVerifyUnsignedArtifactsDetailed_records_non_empty_ocsp_outcomes()
    {
        var (ocspDer, leafPub, issuerPub) =
            BcOcspRevocationTestData.BuildGoodOcspWithIssuerResponderEmbedded(BigInteger.ValueOf(42_030));
        var chain = new[] { leafPub, issuerPub };
        Assert.True(
            EmbeddedRevocationVerifier.TryVerifyUnsignedArtifactsDetailed(
                leafPub,
                [ocspDer],
                [],
                chain,
                out var err,
                out var outcomes),
            err);
        Assert.Single(outcomes);
        Assert.Equal(RevocationArtifactKind.Ocsp, outcomes[0].Kind);
        Assert.Equal(0, outcomes[0].Ordinal);
        Assert.True(outcomes[0].Success);
    }

    [Fact]
    public async Task Strict_embedded_responder_only_rejects_ocsp_without_embedded_certs()
    {
        var (ocspDer, leafPub, issuerPub) = BuildBcOcspGoodNoEmbeddedCerts(BigInteger.ValueOf(42_010));
        var chain = new[] { leafPub, issuerPub };
        var opt = new EmbeddedRevocationVerificationOptions { RequireOcspSignatureByEmbeddedResponderOnly = true };
        Assert.False(
            EmbeddedRevocationVerifier.TryVerifyUnsignedArtifacts(leafPub, [ocspDer], [], chain, out var err, opt),
            err);
        Assert.Contains("embedded", err, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Strict_ocsp_signing_eku_rejects_ca_embedded_responder_without_eku()
    {
        var (ocspDer, leafPub, issuerPub) =
            BcOcspRevocationTestData.BuildGoodOcspWithIssuerResponderEmbedded(BigInteger.ValueOf(42_011));
        var chain = new[] { leafPub, issuerPub };
        var opt = new EmbeddedRevocationVerificationOptions { RequireEmbeddedResponderOcspSigningExtendedKeyUsage = true };
        Assert.False(
            EmbeddedRevocationVerifier.TryVerifyUnsignedArtifacts(leafPub, [ocspDer], [], chain, out var err, opt),
            err);
        Assert.Contains("OCSPSigning", err, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Responder_pkix_validation_accepts_when_embedded_responder_is_trusted_issuer()
    {
        var (ocspDer, leafPub, issuerPub) =
            BcOcspRevocationTestData.BuildGoodOcspWithIssuerResponderEmbedded(BigInteger.ValueOf(42_021));
        var chain = new[] { leafPub, issuerPub };
        var opt = new EmbeddedRevocationVerificationOptions
        {
            ValidateEmbeddedOcspResponderCertificateChain = true,
            ResponderChainTrustAnchors = new X509Certificate2Collection(issuerPub),
        };
        Assert.True(
            EmbeddedRevocationVerifier.TryVerifyUnsignedArtifacts(leafPub, [ocspDer], [], chain, out var err, opt),
            err);
    }

    [Fact]
    public async Task Responder_pkix_validation_rejects_standalone_ocsp_responder_not_under_signer_anchors()
    {
        var (ocspDer, leafPub, issuerPub) =
            BcOcspRevocationTestData.BuildOcspSignedByDedicatedResponder(BigInteger.ValueOf(42_020));
        var chain = new[] { leafPub, issuerPub };
        var opt = new EmbeddedRevocationVerificationOptions
        {
            ValidateEmbeddedOcspResponderCertificateChain = true,
            ResponderChainTrustAnchors = new X509Certificate2Collection(issuerPub),
        };
        Assert.False(
            EmbeddedRevocationVerifier.TryVerifyUnsignedArtifacts(leafPub, [ocspDer], [], chain, out var err, opt),
            err);
        Assert.Contains("PKIX", err, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Responder_pkix_validation_requires_embedded_responder_certificate()
    {
        var (ocspDer, leafPub, issuerPub) = BuildBcOcspGoodNoEmbeddedCerts(BigInteger.ValueOf(42_022));
        var chain = new[] { leafPub, issuerPub };
        var opt = new EmbeddedRevocationVerificationOptions { ValidateEmbeddedOcspResponderCertificateChain = true };
        Assert.False(
            EmbeddedRevocationVerifier.TryVerifyUnsignedArtifacts(leafPub, [ocspDer], [], chain, out var err, opt),
            err);
        Assert.Contains("embedded", err, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task TryVerifyUnsignedArtifacts_rejects_revoked_ocsp()
    {
        var (ocspDer, leafPub, issuerPub) = BuildBcOcspRevoked(BigInteger.ValueOf(42_002));
        var chain = new[] { leafPub, issuerPub };
        Assert.False(EmbeddedRevocationVerifier.TryVerifyUnsignedArtifacts(leafPub, [ocspDer], [], chain, out var err));
        Assert.Contains("revoked", err, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task TryVerifyUnsignedArtifacts_accepts_empty_crl_that_does_not_revoke_leaf()
    {
        var (crlDer, issuerPub, leafPub) = BuildEmptyCrlForLeaf(BigInteger.ValueOf(42_003));
        var chain = new[] { leafPub, issuerPub };
        Assert.True(
            EmbeddedRevocationVerifier.TryVerifyUnsignedArtifacts(leafPub, [], [crlDer], chain, out var err),
            err);
    }

    [Fact]
    public async Task TryVerifyUnsignedArtifacts_rejects_crl_that_revokes_leaf()
    {
        var serial = BigInteger.ValueOf(42_004);
        var (crlDer, issuerPub, leafPub) = BuildCrlRevokingLeaf(serial);
        var chain = new[] { leafPub, issuerPub };
        Assert.False(EmbeddedRevocationVerifier.TryVerifyUnsignedArtifacts(leafPub, [], [crlDer], chain, out var err));
        Assert.Contains("revoked", err, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task TryVerifyUnsignedArtifacts_accepts_crl_signed_by_delegated_issuer_only_in_extra_chain()
    {
        var serial = BigInteger.ValueOf(42_030);
        var (crlDer, leafPub, intermediatePub, rootPub, delegatedPub) = BuildEmptyCrlSignedByDelegatedIssuer(serial);
        var chain = new[] { leafPub, intermediatePub, rootPub };
        var extras = new X509Certificate2Collection(delegatedPub);
        Assert.False(
            EmbeddedRevocationVerifier.TryVerifyUnsignedArtifacts(leafPub, [], [crlDer], chain, out var errWithout),
            errWithout);
        Assert.Contains("PKIX path", errWithout, StringComparison.OrdinalIgnoreCase);
        Assert.True(
            EmbeddedRevocationVerifier.TryVerifyUnsignedArtifacts(leafPub, [], [crlDer], chain, out var errWith, null, extras),
            errWith);
    }

    [Fact]
    public async Task SignatureValidator_embedded_crl_accepts_delegated_crl_signer_in_extra_chain()
    {
        using var rootRsa = RSA.Create(2048);
        var rootReq = new CertificateRequest("CN=Root CRL extra chain", rootRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, false));
        using var root = rootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-3), DateTimeOffset.UtcNow.AddYears(5));

        using var intRsa = RSA.Create(2048);
        var intReq = new CertificateRequest("CN=Int CRL extra chain", intRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        intReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        intReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, false));
        var intNotAfter = new DateTimeOffset(root.NotAfter.ToUniversalTime(), TimeSpan.Zero);
        using var intermediatePub = intReq.Create(root, DateTimeOffset.UtcNow.AddDays(-2), intNotAfter, [42, 2]);
        using var intermediate = intermediatePub.CopyWithPrivateKey(intRsa);

        using var leafRsa = RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=Leaf CRL extra chain", leafRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        var leafSerial = new byte[8];
        RandomNumberGenerator.Fill(leafSerial);
        var leafNotAfter = new DateTimeOffset(intermediate.NotAfter.ToUniversalTime(), TimeSpan.Zero).AddDays(-1);
        using var leafPub = leafReq.Create(
            intermediate,
            DateTimeOffset.UtcNow.AddDays(-1),
            leafNotAfter,
            leafSerial);
        using var leaf = leafPub.CopyWithPrivateKey(leafRsa);

        using var delRsa = RSA.Create(2048);
        var delReq = new CertificateRequest("CN=Delegated CRL signer extra chain", delRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        delReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        delReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.CrlSign, false));
        var delegatedNotAfter = new DateTimeOffset(intermediate.NotAfter.ToUniversalTime() - TimeSpan.FromDays(1), TimeSpan.Zero);
        using var delegated = delReq.Create(
            intermediate,
            DateTimeOffset.UtcNow.AddDays(-1),
            delegatedNotAfter,
            [42, 3]);

        var parser = new X509CertificateParser();
        var delBc = parser.ReadCertificate(delegated.RawData);
        var delKp = DotNetUtilities.GetKeyPair(delRsa);
        var crlGen = new X509V2CrlGenerator();
        crlGen.SetIssuerDN(delBc.SubjectDN);
        crlGen.SetThisUpdate(DateTime.UtcNow.AddHours(-2));
        crlGen.SetNextUpdate(DateTime.UtcNow.AddDays(30));
        var crl = crlGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", delKp.Private));
        var crlDer = crl.GetEncoded();

        var payload = "embedded-crl-extra-chain"u8.ToArray();
        var dataFiles = new[] { new DataFile(new MemoryStream(payload), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dataFiles, leaf, DateTimeOffset.Parse("2025-08-01T12:00:00Z"));
        XadesBesSigner.AppendUnsignedRevocationValues(sig, null, [crlDer]);

        var policy = new SignatureTrustPolicy
        {
            ValidateCertificateChain = true,
            RevocationMode = X509RevocationMode.NoCheck,
            CustomTrustAnchors = new X509Certificate2Collection(root),
            ExtraChainCertificates = new X509Certificate2Collection { intermediate, delegated },
            VerifyUnsignedRevocationWhenPresent = true,
        };

        var result = await SignatureValidator.ValidateAsync(sig, new Dictionary<string, byte[]> { ["doc.txt"] = payload }, policy);
        Assert.True(result.Success, result.Error);
        Assert.True(result.UnsignedRevocationArtifactsValid);
    }

    [Fact]
    public async Task SignatureValidator_runs_embedded_ocsp_when_policy_enabled()
    {
        using var issuerRsa = RSA.Create(2048);
        var issuerReq = new CertificateRequest("CN=CA OCSP embed", issuerRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        issuerReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        issuerReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, false));
        using var issuer = issuerReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddYears(5));

        using var leafRsa = RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=Signer OCSP embed", leafRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        var leafSerial = new byte[8];
        RandomNumberGenerator.Fill(leafSerial);
        using var leafPub = leafReq.Create(issuer, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), leafSerial);
        using var leaf = leafPub.CopyWithPrivateKey(leafRsa);

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

        var payload = "embedded-ocsp-doc"u8.ToArray();
        var dataFiles = new[] { new DataFile(new MemoryStream(payload), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dataFiles, leaf, DateTimeOffset.Parse("2025-07-01T08:00:00Z"));
        XadesBesSigner.AppendUnsignedRevocationValues(sig, [ocspDer], null);

        var policy = new SignatureTrustPolicy
        {
            ValidateCertificateChain = true,
            RevocationMode = X509RevocationMode.NoCheck,
            CustomTrustAnchors = new X509Certificate2Collection(issuer),
            VerifyUnsignedRevocationWhenPresent = true,
            StrictEmbeddedOcspValidateResponderCertificateChain = true,
        };

        var result = await SignatureValidator.ValidateAsync(sig, new Dictionary<string, byte[]> { ["doc.txt"] = payload }, policy);
        Assert.True(result.Success, result.Error);
        Assert.True(result.UnsignedRevocationArtifactsValid);
    }

    [Fact]
    public async Task SignatureValidator_responder_pkix_fails_when_ocsp_signed_by_unanchored_standalone_responder()
    {
        using var issuerRsa = RSA.Create(2048);
        var issuerReq = new CertificateRequest("CN=CA standalone OCSP", issuerRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        issuerReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        issuerReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, false));
        using var issuer = issuerReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddYears(5));

        using var leafRsa = RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=Leaf standalone OCSP", leafRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        var leafSerial = new byte[8];
        RandomNumberGenerator.Fill(leafSerial);
        using var leafPub = leafReq.Create(issuer, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), leafSerial);
        using var leaf = leafPub.CopyWithPrivateKey(leafRsa);

        using var respRsa = RSA.Create(2048);
        var respReq = new CertificateRequest("CN=Standalone OCSP responder", respRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        respReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        respReq.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.9")], false));
        using var responder = respReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var parser = new X509CertificateParser();
        var issuerBc = parser.ReadCertificate(issuer.RawData);
        var leafBc = parser.ReadCertificate(leaf.RawData);
        var responderBc = parser.ReadCertificate(responder.RawData);
        var responderKeyPair = DotNetUtilities.GetKeyPair(respRsa);

#pragma warning disable CS0618
        var certId = new CertificateID(OiwObjectIdentifiers.IdSha1.Id, issuerBc, leafBc.SerialNumber);
#pragma warning restore CS0618
        var basicGen = new BasicOcspRespGenerator(responderKeyPair.Public);
        basicGen.AddResponse(certId, null, DateTime.UtcNow, null, null);
        var basic = basicGen.Generate(
            new Asn1SignatureFactory("SHA256WithRSA", responderKeyPair.Private),
            [responderBc],
            DateTime.UtcNow);
        var ocspDer = new OCSPRespGenerator().Generate(OcspRespStatus.Successful, basic).GetEncoded();

        var payload = "standalone-ocsp-pkix"u8.ToArray();
        var dataFiles = new[] { new DataFile(new MemoryStream(payload), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dataFiles, leaf, DateTimeOffset.Parse("2025-07-01T08:00:00Z"));
        XadesBesSigner.AppendUnsignedRevocationValues(sig, [ocspDer], null);

        var policy = new SignatureTrustPolicy
        {
            ValidateCertificateChain = true,
            RevocationMode = X509RevocationMode.NoCheck,
            CustomTrustAnchors = new X509Certificate2Collection(issuer),
            VerifyUnsignedRevocationWhenPresent = true,
            StrictEmbeddedOcspValidateResponderCertificateChain = true,
        };

        var result = await SignatureValidator.ValidateAsync(sig, new Dictionary<string, byte[]> { ["doc.txt"] = payload }, policy);
        Assert.False(result.Success);
        Assert.Contains("PKIX", result.Error ?? "", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SignatureValidator_strict_embedded_responder_fails_when_ocsp_has_no_embedded_certs()
    {
        using var issuerRsa = RSA.Create(2048);
        var issuerReq = new CertificateRequest("CN=Strict CA", issuerRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        issuerReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        issuerReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, false));
        using var issuer = issuerReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddYears(5));

        using var leafRsa = RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=Strict leaf", leafRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        var leafSerial = new byte[8];
        RandomNumberGenerator.Fill(leafSerial);
        using var leafPub = leafReq.Create(issuer, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), leafSerial);
        using var leaf = leafPub.CopyWithPrivateKey(leafRsa);

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
            Array.Empty<Org.BouncyCastle.X509.X509Certificate>(),
            DateTime.UtcNow);
        var ocspDer = new OCSPRespGenerator().Generate(OcspRespStatus.Successful, basic).GetEncoded();

        var payload = "strict-ocsp"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
            leaf,
            DateTimeOffset.Parse("2025-09-01T08:00:00Z"));
        XadesBesSigner.AppendUnsignedRevocationValues(sig, [ocspDer], null);

        var policy = new SignatureTrustPolicy
        {
            ValidateCertificateChain = true,
            RevocationMode = X509RevocationMode.NoCheck,
            CustomTrustAnchors = new X509Certificate2Collection(issuer),
            VerifyUnsignedRevocationWhenPresent = true,
            StrictEmbeddedOcspRequireEmbeddedResponderSignature = true,
        };

        var result = await SignatureValidator.ValidateAsync(sig, new Dictionary<string, byte[]> { ["doc.txt"] = payload }, policy);
        Assert.False(result.Success);
        Assert.Contains("embedded", result.Error ?? "", StringComparison.OrdinalIgnoreCase);
    }

    private static (byte[] OcspDer, X509Certificate2 LeafPublic, X509Certificate2 IssuerPublic) BuildBcOcspGoodNoEmbeddedCerts(
        BigInteger leafSerial)
    {
        var random = new SecureRandom();
        var keyGen = new RsaKeyPairGenerator();
        keyGen.Init(new KeyGenerationParameters(random, 2048));
        var issuerKp = keyGen.GenerateKeyPair();

        var issuerGen = new X509V3CertificateGenerator();
        issuerGen.SetSerialNumber(BigInteger.One);
        var issuerDn = new X509Name("CN=Embedded OCSP issuer no-embed");
        issuerGen.SetIssuerDN(issuerDn);
        issuerGen.SetSubjectDN(issuerDn);
        issuerGen.SetNotBefore(DateTime.UtcNow.AddDays(-2));
        issuerGen.SetNotAfter(DateTime.UtcNow.AddYears(5));
        issuerGen.SetPublicKey(issuerKp.Public);
        issuerGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(0));
        issuerGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));
        var issuerCert = issuerGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", issuerKp.Private));

        var leafKp = keyGen.GenerateKeyPair();
        var leafGen = new X509V3CertificateGenerator();
        leafGen.SetSerialNumber(leafSerial);
        leafGen.SetIssuerDN(issuerDn);
        leafGen.SetSubjectDN(new X509Name("CN=Embedded OCSP leaf no-embed"));
        leafGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        leafGen.SetPublicKey(leafKp.Public);
        leafGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        var leafCert = leafGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", issuerKp.Private));

#pragma warning disable CS0618
        var certId = new CertificateID(OiwObjectIdentifiers.IdSha1.Id, issuerCert, leafCert.SerialNumber);
#pragma warning restore CS0618
        var basicGen = new BasicOcspRespGenerator(issuerKp.Public);
        basicGen.AddResponse(certId, null, DateTime.UtcNow, null, null);
        var basic = basicGen.Generate(
            new Asn1SignatureFactory("SHA256WithRSA", issuerKp.Private),
            Array.Empty<Org.BouncyCastle.X509.X509Certificate>(),
            DateTime.UtcNow);
        var ocspDer = new OCSPRespGenerator().Generate(OcspRespStatus.Successful, basic).GetEncoded();

        return (ocspDer, new X509Certificate2(leafCert.GetEncoded()), new X509Certificate2(issuerCert.GetEncoded()));
    }

    private static (byte[] OcspDer, X509Certificate2 LeafPublic, X509Certificate2 IssuerPublic) BuildBcOcspRevoked(BigInteger leafSerial)
    {
        var random = new SecureRandom();
        var keyGen = new RsaKeyPairGenerator();
        keyGen.Init(new KeyGenerationParameters(random, 2048));
        var issuerKp = keyGen.GenerateKeyPair();

        var issuerGen = new X509V3CertificateGenerator();
        issuerGen.SetSerialNumber(BigInteger.One);
        var issuerDn = new X509Name("CN=Embedded OCSP issuer revoked");
        issuerGen.SetIssuerDN(issuerDn);
        issuerGen.SetSubjectDN(issuerDn);
        issuerGen.SetNotBefore(DateTime.UtcNow.AddDays(-2));
        issuerGen.SetNotAfter(DateTime.UtcNow.AddYears(5));
        issuerGen.SetPublicKey(issuerKp.Public);
        issuerGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(0));
        issuerGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));
        var issuerCert = issuerGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", issuerKp.Private));

        var leafKp = keyGen.GenerateKeyPair();
        var leafGen = new X509V3CertificateGenerator();
        leafGen.SetSerialNumber(leafSerial);
        leafGen.SetIssuerDN(issuerDn);
        leafGen.SetSubjectDN(new X509Name("CN=Embedded OCSP leaf revoked"));
        leafGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        leafGen.SetPublicKey(leafKp.Public);
        leafGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        var leafCert = leafGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", issuerKp.Private));

#pragma warning disable CS0618
        var certId = new CertificateID(OiwObjectIdentifiers.IdSha1.Id, issuerCert, leafCert.SerialNumber);
#pragma warning restore CS0618
        var basicGen = new BasicOcspRespGenerator(issuerKp.Public);
        basicGen.AddResponse(
            certId,
            new RevokedStatus(DateTime.UtcNow.AddHours(-1), CrlReason.KeyCompromise),
            DateTime.UtcNow,
            null,
            null);
        var basic = basicGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", issuerKp.Private), [issuerCert], DateTime.UtcNow);
        var ocspDer = new OCSPRespGenerator().Generate(OcspRespStatus.Successful, basic).GetEncoded();

        return (ocspDer, new X509Certificate2(leafCert.GetEncoded()), new X509Certificate2(issuerCert.GetEncoded()));
    }

    private static (byte[] CrlDer, X509Certificate2 IssuerPublic, X509Certificate2 LeafPublic) BuildEmptyCrlForLeaf(BigInteger leafSerial)
    {
        var random = new SecureRandom();
        var keyGen = new RsaKeyPairGenerator();
        keyGen.Init(new KeyGenerationParameters(random, 2048));
        var issuerKp = keyGen.GenerateKeyPair();

        var issuerGen = new X509V3CertificateGenerator();
        issuerGen.SetSerialNumber(BigInteger.One);
        var issuerDn = new X509Name("CN=Embedded CRL CA empty");
        issuerGen.SetIssuerDN(issuerDn);
        issuerGen.SetSubjectDN(issuerDn);
        issuerGen.SetNotBefore(DateTime.UtcNow.AddDays(-2));
        issuerGen.SetNotAfter(DateTime.UtcNow.AddYears(5));
        issuerGen.SetPublicKey(issuerKp.Public);
        issuerGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(0));
        issuerGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));
        var issuerCert = issuerGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", issuerKp.Private));

        var leafKp = keyGen.GenerateKeyPair();
        var leafGen = new X509V3CertificateGenerator();
        leafGen.SetSerialNumber(leafSerial);
        leafGen.SetIssuerDN(issuerDn);
        leafGen.SetSubjectDN(new X509Name("CN=Embedded CRL leaf"));
        leafGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        leafGen.SetPublicKey(leafKp.Public);
        leafGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        var leafCert = leafGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", issuerKp.Private));

        var crlGen = new X509V2CrlGenerator();
        crlGen.SetIssuerDN(issuerDn);
        crlGen.SetThisUpdate(DateTime.UtcNow.AddHours(-2));
        crlGen.SetNextUpdate(DateTime.UtcNow.AddDays(30));
        var crl = crlGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", issuerKp.Private));

        return (crl.GetEncoded(), new X509Certificate2(issuerCert.GetEncoded()), new X509Certificate2(leafCert.GetEncoded()));
    }

    private static (byte[] CrlDer, X509Certificate2 IssuerPublic, X509Certificate2 LeafPublic) BuildCrlRevokingLeaf(BigInteger leafSerial)
    {
        var random = new SecureRandom();
        var keyGen = new RsaKeyPairGenerator();
        keyGen.Init(new KeyGenerationParameters(random, 2048));
        var issuerKp = keyGen.GenerateKeyPair();

        var issuerGen = new X509V3CertificateGenerator();
        issuerGen.SetSerialNumber(BigInteger.One);
        var issuerDn = new X509Name("CN=Embedded CRL CA revoke");
        issuerGen.SetIssuerDN(issuerDn);
        issuerGen.SetSubjectDN(issuerDn);
        issuerGen.SetNotBefore(DateTime.UtcNow.AddDays(-2));
        issuerGen.SetNotAfter(DateTime.UtcNow.AddYears(5));
        issuerGen.SetPublicKey(issuerKp.Public);
        issuerGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(0));
        issuerGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));
        var issuerCert = issuerGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", issuerKp.Private));

        var leafKp = keyGen.GenerateKeyPair();
        var leafGen = new X509V3CertificateGenerator();
        leafGen.SetSerialNumber(leafSerial);
        leafGen.SetIssuerDN(issuerDn);
        leafGen.SetSubjectDN(new X509Name("CN=Embedded CRL leaf revoked"));
        leafGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        leafGen.SetPublicKey(leafKp.Public);
        leafGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        var leafCert = leafGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", issuerKp.Private));

        var crlGen = new X509V2CrlGenerator();
        crlGen.SetIssuerDN(issuerDn);
        crlGen.SetThisUpdate(DateTime.UtcNow.AddHours(-2));
        crlGen.SetNextUpdate(DateTime.UtcNow.AddDays(30));
        crlGen.AddCrlEntry(leafSerial, DateTime.UtcNow.AddHours(-1), CrlReason.KeyCompromise);
        var crl = crlGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", issuerKp.Private));

        return (crl.GetEncoded(), new X509Certificate2(issuerCert.GetEncoded()), new X509Certificate2(leafCert.GetEncoded()));
    }

    private static (
        byte[] CrlDer,
        X509Certificate2 LeafPublic,
        X509Certificate2 IntermediatePublic,
        X509Certificate2 RootPublic,
        X509Certificate2 DelegatedCrlIssuerPublic) BuildEmptyCrlSignedByDelegatedIssuer(BigInteger leafSerial)
    {
        var random = new SecureRandom();
        var keyGen = new RsaKeyPairGenerator();
        keyGen.Init(new KeyGenerationParameters(random, 2048));

        var rootKp = keyGen.GenerateKeyPair();
        var rootDn = new X509Name("CN=Embedded CRL root delegated");
        var rootGen = new X509V3CertificateGenerator();
        rootGen.SetSerialNumber(BigInteger.One);
        rootGen.SetIssuerDN(rootDn);
        rootGen.SetSubjectDN(rootDn);
        rootGen.SetNotBefore(DateTime.UtcNow.AddDays(-2));
        rootGen.SetNotAfter(DateTime.UtcNow.AddYears(5));
        rootGen.SetPublicKey(rootKp.Public);
        rootGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(0));
        rootGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));
        var rootCert = rootGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", rootKp.Private));

        var intKp = keyGen.GenerateKeyPair();
        var intDn = new X509Name("CN=Embedded CRL intermediate delegated");
        var intGen = new X509V3CertificateGenerator();
        intGen.SetSerialNumber(BigInteger.Two);
        intGen.SetIssuerDN(rootDn);
        intGen.SetSubjectDN(intDn);
        intGen.SetNotBefore(DateTime.UtcNow.AddDays(-2));
        intGen.SetNotAfter(DateTime.UtcNow.AddYears(5));
        intGen.SetPublicKey(intKp.Public);
        intGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(0));
        intGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));
        var intCert = intGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", rootKp.Private));

        var leafKp = keyGen.GenerateKeyPair();
        var leafGen = new X509V3CertificateGenerator();
        leafGen.SetSerialNumber(leafSerial);
        leafGen.SetIssuerDN(intDn);
        leafGen.SetSubjectDN(new X509Name("CN=Embedded CRL leaf delegated"));
        leafGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        leafGen.SetPublicKey(leafKp.Public);
        leafGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        var leafCert = leafGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", intKp.Private));

        var delKp = keyGen.GenerateKeyPair();
        var delDn = new X509Name("CN=Delegated CRL signer BC");
        var delGen = new X509V3CertificateGenerator();
        delGen.SetSerialNumber(BigInteger.Three);
        delGen.SetIssuerDN(intDn);
        delGen.SetSubjectDN(delDn);
        delGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        delGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        delGen.SetPublicKey(delKp.Public);
        delGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        delGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.CrlSign));
        var delCert = delGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", intKp.Private));

        var crlGen = new X509V2CrlGenerator();
        crlGen.SetIssuerDN(delDn);
        crlGen.SetThisUpdate(DateTime.UtcNow.AddHours(-2));
        crlGen.SetNextUpdate(DateTime.UtcNow.AddDays(30));
        var crl = crlGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", delKp.Private));

        return (
            crl.GetEncoded(),
            new X509Certificate2(leafCert.GetEncoded()),
            new X509Certificate2(intCert.GetEncoded()),
            new X509Certificate2(rootCert.GetEncoded()),
            new X509Certificate2(delCert.GetEncoded()));
    }
}
