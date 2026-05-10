using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace eDocLib;

/// <summary>BC-generated OCSP fixtures shared by embedded and online revocation tests.</summary>
internal static class BcOcspRevocationTestData
{
    /// <summary>OCSP signed by the issuing CA key; embedded responder cert is the CA certificate.</summary>
    public static (byte[] OcspDer, X509Certificate2 LeafPublic, X509Certificate2 IssuerPublic) BuildGoodOcspWithIssuerResponderEmbedded(
        BigInteger leafSerial)
    {
        var random = new SecureRandom();
        var keyGen = new RsaKeyPairGenerator();
        keyGen.Init(new KeyGenerationParameters(random, 2048));
        var issuerKp = keyGen.GenerateKeyPair();

        var issuerGen = new X509V3CertificateGenerator();
        issuerGen.SetSerialNumber(BigInteger.One);
        var issuerDn = new X509Name("CN=Embedded OCSP issuer");
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
        leafGen.SetSubjectDN(new X509Name("CN=Embedded OCSP leaf"));
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
        var basic = basicGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", issuerKp.Private), [issuerCert], DateTime.UtcNow);
        var ocspDer = new OCSPRespGenerator().Generate(OcspRespStatus.Successful, basic).GetEncoded();

        return (ocspDer, new X509Certificate2(leafCert.GetEncoded()), new X509Certificate2(issuerCert.GetEncoded()));
    }

    /// <summary>Leaf issuer unchanged; OCSP signed by a self-contained responder with id-kp-OCSPSigning (not the CA).</summary>
    public static (byte[] OcspDer, X509Certificate2 LeafPublic, X509Certificate2 IssuerPublic) BuildOcspSignedByDedicatedResponder(
        BigInteger leafSerial)
    {
        var random = new SecureRandom();
        var keyGen = new RsaKeyPairGenerator();
        keyGen.Init(new KeyGenerationParameters(random, 2048));
        var issuerKp = keyGen.GenerateKeyPair();

        var issuerGen = new X509V3CertificateGenerator();
        issuerGen.SetSerialNumber(BigInteger.One);
        var issuerDn = new X509Name("CN=Embedded OCSP issuer dedicated resp");
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
        leafGen.SetSubjectDN(new X509Name("CN=Embedded OCSP leaf dedicated resp"));
        leafGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        leafGen.SetPublicKey(leafKp.Public);
        leafGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        var leafCert = leafGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", issuerKp.Private));

        var respKp = keyGen.GenerateKeyPair();
        var respDn = new X509Name("CN=Standalone dedicated OCSP");
        var respGen = new X509V3CertificateGenerator();
        respGen.SetSerialNumber(BigInteger.Two);
        respGen.SetIssuerDN(respDn);
        respGen.SetSubjectDN(respDn);
        respGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        respGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        respGen.SetPublicKey(respKp.Public);
        respGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        respGen.AddExtension(
            X509Extensions.ExtendedKeyUsage,
            false,
            new ExtendedKeyUsage(new[] { new DerObjectIdentifier("1.3.6.1.5.5.7.3.9") }));
        var responderCert = respGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", respKp.Private));

#pragma warning disable CS0618
        var certId = new CertificateID(OiwObjectIdentifiers.IdSha1.Id, issuerCert, leafCert.SerialNumber);
#pragma warning restore CS0618
        var basicGen = new BasicOcspRespGenerator(respKp.Public);
        basicGen.AddResponse(certId, null, DateTime.UtcNow, null, null);
        var basic = basicGen.Generate(
            new Asn1SignatureFactory("SHA256WithRSA", respKp.Private),
            [responderCert],
            DateTime.UtcNow);
        var ocspDer = new OCSPRespGenerator().Generate(OcspRespStatus.Successful, basic).GetEncoded();

        return (ocspDer, new X509Certificate2(leafCert.GetEncoded()), new X509Certificate2(issuerCert.GetEncoded()));
    }
}
