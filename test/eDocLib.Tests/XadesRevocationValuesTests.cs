using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using eDocLib.Asic.Container;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib;

public class XadesRevocationValuesTests
{
    [Fact]
    public void AppendUnsignedRevocationValues_crl_only_wraps_in_CRLValues()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=rv-crl", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "rv1"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2024-09-01T08:00:00Z"));

        var crlDer = new byte[] { 0x30, 0x03, 0x01, 0x01, 0xff };
        XadesBesSigner.AppendUnsignedRevocationValues(sig, ocspResponseDer: null, crlDer: new[] { crlDer });

        using var ms = new MemoryStream();
        sig.WriteTo(ms);
        var doc = new XmlDocument { PreserveWhitespace = false };
        doc.LoadXml(Encoding.UTF8.GetString(ms.ToArray()));

        var nsm = new XmlNamespaceManager(doc.NameTable);
        nsm.AddNamespace("xades", XadesSignature.XadesNamespaceUrl);
        Assert.NotNull(doc.SelectSingleNode("//xades:RevocationValues/xades:CRLValues/xades:EncapsulatedCRLValue", nsm));
        Assert.Null(doc.SelectSingleNode("//xades:OCSPValues", nsm));

        var b64 = doc.SelectSingleNode("//xades:EncapsulatedCRLValue", nsm)!.InnerText.Trim();
        Assert.Equal(crlDer, Convert.FromBase64String(b64));
    }

    [Fact]
    public void AppendUnsignedRevocationValues_ocsp_and_crl_both_present()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=rv-both", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var dfs = new[] { new DataFile(new MemoryStream("x"u8.ToArray()), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2024-09-02T08:00:00Z"));

        var ocsp = new byte[] { 0x30, 0x05, 0x02, 0x01, 0x01 };
        var crl = new byte[] { 0x30, 0x04, 0x02, 0x02, 0x00, 0x01 };
        XadesBesSigner.AppendUnsignedRevocationValues(sig, new[] { ocsp }, new[] { crl });

        var owner = sig.GetSignatureOwnerDocument();
        var nsm = new XmlNamespaceManager(owner.NameTable);
        nsm.AddNamespace("xades", XadesSignature.XadesNamespaceUrl);
        Assert.NotNull(owner.SelectSingleNode("//xades:RevocationValues/xades:CRLValues", nsm));
        Assert.NotNull(owner.SelectSingleNode("//xades:RevocationValues/xades:OCSPValues", nsm));
        var ocspNodes = owner.SelectNodes("//xades:EncapsulatedOCSPValue", nsm);
        Assert.Equal(1, ocspNodes!.Count);
    }

    [Fact]
    public async Task AppendUnsignedRevocationValues_merges_with_certificate_values_and_timestamp()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=rv-merge", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var dfs = new[] { new DataFile(new MemoryStream("m"u8.ToArray()), "doc.txt", "text/plain") };
        var tsp = new LocalSha256Rfc3161TimestampProvider();

        var sig = await XadesBesSigner.SignWithTimestampAsync(
            dfs,
            cert,
            DateTimeOffset.Parse("2024-09-03T08:00:00Z"),
            tsp);

        XadesBesSigner.AppendUnsignedCertificateValues(sig, new[] { cert });
        XadesBesSigner.AppendUnsignedRevocationValues(sig, crlDer: new[] { new byte[] { 0xab, 0xcd } });

        var owner = sig.GetSignatureOwnerDocument();
        Assert.Equal(1, owner.GetElementsByTagName("UnsignedProperties", XadesSignature.XadesNamespaceUrl).Count);

        var nsm = new XmlNamespaceManager(owner.NameTable);
        nsm.AddNamespace("xades", XadesSignature.XadesNamespaceUrl);
        Assert.NotNull(owner.SelectSingleNode("//xades:EncapsulatedTimeStamp", nsm));
        Assert.NotNull(owner.SelectSingleNode("//xades:CertificateValues", nsm));
        Assert.NotNull(owner.SelectSingleNode("//xades:RevocationValues", nsm));
    }

    [Fact]
    public void AppendUnsignedRevocationValues_throws_when_no_non_empty_blobs()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=rv-empty", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream("e"u8.ToArray()), "doc.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2024-09-04T08:00:00Z"));

        Assert.Throws<ArgumentException>(() =>
            XadesBesSigner.AppendUnsignedRevocationValues(sig, Array.Empty<byte[]>(), Array.Empty<byte[]>()));
    }
}
