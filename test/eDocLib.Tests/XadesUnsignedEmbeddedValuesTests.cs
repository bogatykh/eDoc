using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using eDocLib.Asic.Container;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib;

public class XadesUnsignedEmbeddedValuesTests
{
    [Fact]
    public void RoundTrip_certificate_and_revocation_der_matches_append_helpers()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=emb", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var dfs = new[] { new DataFile(new MemoryStream("u"u8.ToArray()), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2024-10-01T12:00:00Z"));

        var ocsp = new byte[] { 0x30, 0x03, 0x01, 0x01, 0x02 };
        var crl = new byte[] { 0x30, 0x03, 0x01, 0x01, 0x03 };
        XadesBesSigner.AppendUnsignedCertificateValues(sig, new[] { cert });
        XadesBesSigner.AppendUnsignedRevocationValues(sig, new[] { ocsp }, new[] { crl });

        Assert.Single(sig.UnsignedEncapsulatedX509Der);
        Assert.Equal(cert.RawData, sig.UnsignedEncapsulatedX509Der[0]);

        Assert.Single(sig.UnsignedEncapsulatedOcspDer);
        Assert.Equal(ocsp, sig.UnsignedEncapsulatedOcspDer[0]);

        Assert.Single(sig.UnsignedEncapsulatedCrlDer);
        Assert.Equal(crl, sig.UnsignedEncapsulatedCrlDer[0]);
    }

    [Fact]
    public void ReadEncapsulatedX509Certificates_parses_reload_from_xml()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=reload", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream("r"u8.ToArray()), "doc.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2024-10-02T12:00:00Z"));
        XadesBesSigner.AppendUnsignedCertificateValues(sig, new[] { cert });

        using var ms = new MemoryStream();
        sig.WriteTo(ms);
        var doc = new XmlDocument { PreserveWhitespace = false };
        doc.LoadXml(Encoding.UTF8.GetString(ms.ToArray()));

        var parsed = XadesUnsignedEmbeddedValues.ReadEncapsulatedX509Certificates(doc);
        Assert.Single(parsed);
        Assert.Equal(cert.RawData, parsed[0]);

        var roundTrip = new XadesSignature(doc);
        Assert.Equal(parsed[0], roundTrip.UnsignedEncapsulatedX509Der[0]);
    }

    [Fact]
    public void Empty_document_returns_empty_lists()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=empty-emb", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream("e"u8.ToArray()), "doc.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2024-10-03T12:00:00Z"));

        Assert.Empty(sig.UnsignedEncapsulatedX509Der);
        Assert.Empty(sig.UnsignedEncapsulatedOcspDer);
        Assert.Empty(sig.UnsignedEncapsulatedCrlDer);
    }
}
