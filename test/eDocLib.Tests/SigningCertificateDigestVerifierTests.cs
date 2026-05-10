using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using eDocLib.Asic.Container;
using eDocLib.Validation;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib;

public class SigningCertificateDigestVerifierTests
{
    [Fact]
    public void Full_signature_includes_signing_certificate_and_verifies()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=ESS test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "payload"u8.ToArray();
        var dataFiles = new[] { new DataFile(new MemoryStream(payload), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dataFiles, cert, DateTimeOffset.Parse("2025-06-01T10:00:00Z"));

        var owner = sig.GetSignatureOwnerDocument();
        var nsm = new XmlNamespaceManager(owner.NameTable ?? new NameTable());
        nsm.AddNamespace("xades", XadesSignature.XadesNamespaceUrl);
        Assert.NotNull(owner.SelectSingleNode("//xades:SigningCertificate", nsm));

        Assert.True(DetachedSignatureVerifier.TryVerify(sig, new Dictionary<string, byte[]> { ["doc.txt"] = payload }, out var err), err);
        Assert.True(
            DetachedSignatureVerifier.TryVerify(
                sig,
                new Dictionary<string, byte[]> { ["doc.txt"] = payload },
                out err,
                new SignatureTrustPolicy { RequireXadesSigningCertificate = true }),
            err);
    }

    [Fact]
    public void TryVerifyIfPresent_rejects_wrong_cert_digest()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=ESS digest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var doc = BuildMinimalSigningCertificateDoc(cert, wrongDigest: true);
        Assert.False(SigningCertificateDigestVerifier.TryVerifyIfPresent(doc, cert, requireElement: false, out var err));
        Assert.Contains("CertDigest", err, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryVerifyIfPresent_requires_element_when_configured()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=no ESS", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var doc = new XmlDocument();
        doc.AppendChild(doc.CreateElement("root"));
        Assert.True(SigningCertificateDigestVerifier.TryVerifyIfPresent(doc, cert, requireElement: false, out _));
        Assert.False(SigningCertificateDigestVerifier.TryVerifyIfPresent(doc, cert, requireElement: true, out var err));
        Assert.Contains("missing", err, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryVerifyIfPresent_sha384_rejected_when_policy_restricts_to_sha256()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=ESS sha384", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var doc = BuildMinimalSigningCertificateDoc(cert, digestAlgorithmUri: SignedXml.XmlDsigSHA384Url);
        Assert.True(SigningCertificateDigestVerifier.TryVerifyIfPresent(doc, cert, requireElement: false, out _, allowSha384CertDigest: true));
        Assert.False(SigningCertificateDigestVerifier.TryVerifyIfPresent(doc, cert, requireElement: false, out var err, allowSha384CertDigest: false));
        Assert.Contains("SHA-256 only", err, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DetachedSignatureVerifier_honors_RestrictSigningCertificateDigestToSha256()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=ESS policy", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "p"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2025-07-01T10:00:00Z"));
        var owner = sig.GetSignatureOwnerDocument();
        var nsm = new XmlNamespaceManager(owner.NameTable ?? new NameTable());
        nsm.AddNamespace("xades", XadesSignature.XadesNamespaceUrl);
        nsm.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
        Assert.NotNull(owner.SelectSingleNode("//xades:CertDigest/ds:DigestMethod", nsm));
        var dm = (XmlElement)owner.SelectSingleNode("//xades:CertDigest/ds:DigestMethod", nsm)!;
        dm.SetAttribute("Algorithm", SignedXml.XmlDsigSHA384Url);
        Assert.NotNull(owner.SelectSingleNode("//xades:CertDigest/ds:DigestValue", nsm));
        var dv = (XmlElement)owner.SelectSingleNode("//xades:CertDigest/ds:DigestValue", nsm)!;
        dv.InnerText = Convert.ToBase64String(SHA384.HashData(cert.RawData));
        var mutated = new AsicSignature(owner);
        Assert.False(
            DetachedSignatureVerifier.TryVerify(
                mutated,
                new Dictionary<string, byte[]> { ["doc.txt"] = payload },
                out var err,
                new SignatureTrustPolicy { RestrictSigningCertificateDigestToSha256 = true }),
            err);
    }

    [Fact]
    public void TryVerifyIfPresent_rejects_empty_signing_certificate_wrapper()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=empty ESS", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var doc = new XmlDocument();
        var root = doc.CreateElement("root");
        doc.AppendChild(root);
        var sc = doc.CreateElement(XadesSignature.XadesPrefix, "SigningCertificate", XadesSignature.XadesNamespaceUrl);
        root.AppendChild(sc);

        Assert.False(SigningCertificateDigestVerifier.TryVerifyIfPresent(doc, cert, requireElement: false, out var err));
        Assert.Contains("no xades:Cert", err, StringComparison.OrdinalIgnoreCase);
    }

    private static XmlDocument BuildMinimalSigningCertificateDoc(X509Certificate2 cert, bool wrongDigest = false, string? digestAlgorithmUri = null)
    {
        var doc = new XmlDocument();
        var root = doc.CreateElement("root");
        doc.AppendChild(root);
        var sc = doc.CreateElement(XadesSignature.XadesPrefix, "SigningCertificate", XadesSignature.XadesNamespaceUrl);
        root.AppendChild(sc);
        var certEl = doc.CreateElement(XadesSignature.XadesPrefix, "Cert", XadesSignature.XadesNamespaceUrl);
        sc.AppendChild(certEl);
        var ds = SignedXml.XmlDsigNamespaceUrl;
        var certDigest = doc.CreateElement(XadesSignature.XadesPrefix, "CertDigest", XadesSignature.XadesNamespaceUrl);
        certEl.AppendChild(certDigest);
        var dm = doc.CreateElement("ds", "DigestMethod", ds);
        var alg = digestAlgorithmUri ?? SignedXml.XmlDsigSHA256Url;
        dm.SetAttribute("Algorithm", alg);
        certDigest.AppendChild(dm);
        var dv = doc.CreateElement("ds", "DigestValue", ds);
        var digest = string.Equals(alg, SignedXml.XmlDsigSHA384Url, StringComparison.Ordinal)
            ? SHA384.HashData(cert.RawData)
            : SHA256.HashData(cert.RawData);
        if (wrongDigest)
        {
            digest[0] ^= 0xFF;
        }

        dv.InnerText = Convert.ToBase64String(digest);
        certDigest.AppendChild(dv);

        var issuerSerial = doc.CreateElement(XadesSignature.XadesPrefix, "IssuerSerial", XadesSignature.XadesNamespaceUrl);
        certEl.AppendChild(issuerSerial);
        var issuerName = doc.CreateElement("ds", "X509IssuerName", ds);
        issuerName.InnerText = cert.Issuer;
        issuerSerial.AppendChild(issuerName);
        var serial = doc.CreateElement("ds", "X509SerialNumber", ds);
        serial.InnerText = GetSerialDecimal(cert);
        issuerSerial.AppendChild(serial);

        return doc;
    }

    private static string GetSerialDecimal(X509Certificate2 cert)
    {
        var le = cert.GetSerialNumber();
        if (le.Length == 0)
        {
            return "0";
        }

        var be = (byte[])le.Clone();
        Array.Reverse(be);
        return new System.Numerics.BigInteger(be, isUnsigned: true, isBigEndian: true)
            .ToString(System.Globalization.CultureInfo.InvariantCulture);
    }
}
