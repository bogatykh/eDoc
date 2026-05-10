using System.Security.Cryptography.X509Certificates;
using eDocLib.Revocation;
using eDocLib.Revocation.Protocols.Crl;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Xunit;

namespace eDocLib;

public class CrlInspectorTests
{
    [Fact]
    public void X509CrlInspector_parse_verify_and_revoked_flag()
    {
        var (crlDer, issuerPub, leafPub) = BuildCrlWithOneRevokedEntry(BigInteger.ValueOf(555));
        Assert.True(X509CrlInspector.TryParse(crlDer, out var crl, out var parseErr), parseErr);
        Assert.NotNull(crl);
        Assert.True(X509CrlInspector.TryVerifyIssuerSignature(crl!, issuerPub, out var sigErr), sigErr);
        Assert.True(X509CrlInspector.IsCertificateRevoked(crl!, leafPub));
    }

    [Fact]
    public void X509CrlInspector_not_revoked_when_serial_absent()
    {
        var (crlDer, issuerPub, _, otherLeafPub) = BuildCrlWithOneRevokedEntryAndOtherLeaf(BigInteger.ValueOf(777));
        Assert.True(X509CrlInspector.TryParse(crlDer, out var crl, out var perr), perr);
        Assert.NotNull(crl);
        Assert.True(X509CrlInspector.TryVerifyIssuerSignature(crl!, issuerPub, out _));
        Assert.False(X509CrlInspector.IsCertificateRevoked(crl!, otherLeafPub));
    }

    private static (byte[] CrlDer, X509Certificate2 IssuerPublic, X509Certificate2 LeafPublic) BuildCrlWithOneRevokedEntry(BigInteger revokedLeafSerial)
    {
        var (issuerKp, issuerCert, issuerDn, _, leafPub) = BuildIssuerAndLeaf(revokedLeafSerial);
        var crlGen = new X509V2CrlGenerator();
        crlGen.SetIssuerDN(issuerDn);
        crlGen.SetThisUpdate(DateTime.UtcNow.AddHours(-2));
        crlGen.SetNextUpdate(DateTime.UtcNow.AddDays(30));
        crlGen.AddCrlEntry(revokedLeafSerial, DateTime.UtcNow.AddHours(-1), CrlReason.KeyCompromise);
        var crl = crlGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", issuerKp.Private));
        var issuerPub = new X509Certificate2(issuerCert.GetEncoded());
        return (crl.GetEncoded(), issuerPub, leafPub);
    }

    private static (byte[] CrlDer, X509Certificate2 IssuerPublic, X509Certificate2 RevokedLeafPublic, X509Certificate2 OtherLeafPublic)
        BuildCrlWithOneRevokedEntryAndOtherLeaf(BigInteger revokedSerial)
    {
        var random = new SecureRandom();
        var keyGen = new RsaKeyPairGenerator();
        keyGen.Init(new KeyGenerationParameters(random, 2048));
        var issuerKp = keyGen.GenerateKeyPair();

        var issuerGen = new X509V3CertificateGenerator();
        issuerGen.SetSerialNumber(BigInteger.One);
        var issuerDn = new X509Name("CN=CRL test CA");
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
        leafGen.SetSerialNumber(revokedSerial);
        leafGen.SetIssuerDN(issuerDn);
        leafGen.SetSubjectDN(new X509Name("CN=revoked leaf"));
        leafGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        leafGen.SetPublicKey(leafKp.Public);
        leafGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        var leafCert = leafGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", issuerKp.Private));
        var leafPub = new X509Certificate2(leafCert.GetEncoded());

        var otherKp = keyGen.GenerateKeyPair();
        var otherGen = new X509V3CertificateGenerator();
        otherGen.SetSerialNumber(BigInteger.ValueOf(8888));
        otherGen.SetIssuerDN(issuerDn);
        otherGen.SetSubjectDN(new X509Name("CN=other leaf"));
        otherGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        otherGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        otherGen.SetPublicKey(otherKp.Public);
        otherGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        var otherCert = otherGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", issuerKp.Private));
        var otherPub = new X509Certificate2(otherCert.GetEncoded());

        var crlGen = new X509V2CrlGenerator();
        crlGen.SetIssuerDN(issuerDn);
        crlGen.SetThisUpdate(DateTime.UtcNow.AddHours(-2));
        crlGen.SetNextUpdate(DateTime.UtcNow.AddDays(30));
        crlGen.AddCrlEntry(revokedSerial, DateTime.UtcNow.AddHours(-1), CrlReason.KeyCompromise);
        var crl = crlGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", issuerKp.Private));

        return (crl.GetEncoded(), new X509Certificate2(issuerCert.GetEncoded()), leafPub, otherPub);
    }

    private static (
        AsymmetricCipherKeyPair IssuerKp,
        Org.BouncyCastle.X509.X509Certificate IssuerCert,
        X509Name IssuerDn,
        Org.BouncyCastle.X509.X509Certificate LeafCert,
        X509Certificate2 LeafPublic)
        BuildIssuerAndLeaf(BigInteger leafSerial)
    {
        var random = new SecureRandom();
        var keyGen = new RsaKeyPairGenerator();
        keyGen.Init(new KeyGenerationParameters(random, 2048));
        var issuerKp = keyGen.GenerateKeyPair();

        var issuerGen = new X509V3CertificateGenerator();
        issuerGen.SetSerialNumber(BigInteger.One);
        var issuerDn = new X509Name("CN=CRL test CA 2");
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
        leafGen.SetSubjectDN(new X509Name("CN=leaf on crl"));
        leafGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        leafGen.SetPublicKey(leafKp.Public);
        leafGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        var leafCert = leafGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", issuerKp.Private));
        var leafPub = new X509Certificate2(leafCert.GetEncoded());

        return (issuerKp, issuerCert, issuerDn, leafCert, leafPub);
    }
}
