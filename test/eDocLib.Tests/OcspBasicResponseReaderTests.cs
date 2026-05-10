using System.Security.Cryptography.X509Certificates;
using eDocLib.Revocation;
using eDocLib.Revocation.Protocols.Ocsp;
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

public class OcspBasicResponseReaderTests
{
    [Fact]
    public void TryReadBasicSingleResponses_fails_when_no_response_bytes()
    {
        var der = new byte[] { 0x30, 0x03, 0x0A, 0x01, 0x00 };
        Assert.False(OcspResponseReader.TryReadBasicSingleResponses(der, out _));
    }

    [Fact]
    public void TryReadBasicSingleResponses_reads_good_status_and_serial()
    {
        var (der, _) = BuildSignedOcspResponseGood(BigInteger.ValueOf(4242));
        Assert.True(OcspResponseReader.TryReadBasicSingleResponses(der, out var entries));
        Assert.NotNull(entries);
        Assert.Single(entries!);
        Assert.Equal(OcspCertificateStatusKind.Good, entries[0].Status);
        Assert.Null(entries[0].RevokedAt);
        var expectedSerial = BigInteger.ValueOf(4242).ToByteArrayUnsigned();
        Assert.Equal(expectedSerial, entries[0].CertificateSerialNumber);
    }

    [Fact]
    public void OcspResponseSignatureVerifier_accepts_issuer_public_cert()
    {
        var (der, issuer) = BuildSignedOcspResponseGood(BigInteger.ValueOf(99));
        Assert.True(OcspResponseSignatureVerifier.TryVerifyBasicSignature(der, issuer, out var err), err);
    }

    [Fact]
    public void OcspResponseSignatureVerifier_accepts_embedded_responder_cert()
    {
        var (der, _) = BuildSignedOcspResponseGood(BigInteger.ValueOf(100));
        Assert.True(OcspResponseSignatureVerifier.TryVerifyBasicSignatureUsingEmbeddedResponderCert(der, out var err), err);
    }

    [Fact]
    public void OcspResponseSignatureVerifier_rejects_truncated_response()
    {
        var (der, issuer) = BuildSignedOcspResponseGood(BigInteger.ValueOf(101));
        Assert.True(der.Length > 40);
        var truncated = der.AsSpan(0, der.Length - 40).ToArray();
        Assert.False(OcspResponseSignatureVerifier.TryVerifyBasicSignature(truncated, issuer, out _));
    }

    private static (byte[] Der, X509Certificate2 IssuerPublicOnly) BuildSignedOcspResponseGood(BigInteger leafSerial)
    {
        var random = new SecureRandom();
        var keyGen = new RsaKeyPairGenerator();
        keyGen.Init(new KeyGenerationParameters(random, 2048));
        var issuerKp = keyGen.GenerateKeyPair();

        var issuerGen = new X509V3CertificateGenerator();
        issuerGen.SetSerialNumber(BigInteger.One);
        var issuerDn = new X509Name("CN=OCSP test issuer");
        issuerGen.SetIssuerDN(issuerDn);
        issuerGen.SetSubjectDN(issuerDn);
        issuerGen.SetNotBefore(DateTime.UtcNow.AddDays(-2));
        issuerGen.SetNotAfter(DateTime.UtcNow.AddYears(5));
        issuerGen.SetPublicKey(issuerKp.Public);
        issuerGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(0));
        issuerGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));
        var issuerCert = issuerGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", issuerKp.Private));

        var leafGen = new X509V3CertificateGenerator();
        leafGen.SetSerialNumber(leafSerial);
        leafGen.SetIssuerDN(issuerDn);
        leafGen.SetSubjectDN(new X509Name("CN=OCSP test leaf"));
        leafGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        var leafKp = keyGen.GenerateKeyPair();
        leafGen.SetPublicKey(leafKp.Public);
        leafGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        var leafCert = leafGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", issuerKp.Private));

#pragma warning disable CS0618
        var certId = new CertificateID(OiwObjectIdentifiers.IdSha1.Id, issuerCert, leafCert.SerialNumber);
#pragma warning restore CS0618

        var basicGen = new BasicOcspRespGenerator(issuerKp.Public);
        basicGen.AddResponse(certId, null, DateTime.UtcNow, null, null);
        var basic = basicGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", issuerKp.Private), new[] { issuerCert }, DateTime.UtcNow);

        var ocspGen = new OCSPRespGenerator();
        var ocspResp = ocspGen.Generate(OcspRespStatus.Successful, basic);
        var issuerDotNet = new X509Certificate2(issuerCert.GetEncoded());
        return (ocspResp.GetEncoded(), issuerDotNet);
    }
}
