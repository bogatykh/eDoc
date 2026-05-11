using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using eDocLib.Asic.Container;
using eDocLib.Timestamp;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib;

public class XadesCertificateValuesTests
{
    [Fact]
    public async Task AppendUnsignedCertificateValues_adds_encapsulated_x509_under_CertificateValues()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=cv-bes", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "cv"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2024-08-01T10:00:00Z"));

        XadesBesSigner.AppendUnsignedCertificateValues(sig, new[] { cert });

        using var ms = new MemoryStream();
        sig.WriteTo(ms);
        var doc = new XmlDocument { PreserveWhitespace = false };
        doc.LoadXml(Encoding.UTF8.GetString(ms.ToArray()));

        var nsm = new XmlNamespaceManager(doc.NameTable);
        nsm.AddNamespace("xades", XadesSignature.XadesNamespaceUrl);
        var certValues = doc.SelectSingleNode("//xades:CertificateValues", nsm);
        Assert.NotNull(certValues);
        var enc = doc.SelectNodes("//xades:EncapsulatedX509Certificate", nsm);
        Assert.NotNull(enc);
        Assert.Equal(1, enc!.Count);
        var roundTrip = new X509Certificate2(Convert.FromBase64String(enc[0]!.InnerText.Trim()));
        Assert.Equal(cert.Thumbprint, roundTrip.Thumbprint);
    }

    [Fact]
    public async Task AppendUnsignedCertificateValues_merges_with_unsigned_properties_after_timestamp()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=cv-t", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "cv-ts"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var tsp = new LocalSha256Rfc3161TimestampProvider();

        var sig = await XadesBesSigner.SignWithTimestampAsync(
            dfs,
            cert,
            DateTimeOffset.Parse("2024-08-02T11:00:00Z"),
            tsp);

        XadesBesSigner.AppendUnsignedCertificateValues(sig, new[] { cert });

        var owner = sig.GetSignatureOwnerDocument();
        var unsignedPropsList = owner.GetElementsByTagName("UnsignedProperties", XadesSignature.XadesNamespaceUrl);
        Assert.Equal(1, unsignedPropsList.Count);

        var nsm = new XmlNamespaceManager(owner.NameTable);
        nsm.AddNamespace("xades", XadesSignature.XadesNamespaceUrl);
        var tsNodes = owner.SelectNodes("//xades:EncapsulatedTimeStamp", nsm);
        var certNodes = owner.SelectNodes("//xades:EncapsulatedX509Certificate", nsm);
        Assert.NotNull(tsNodes);
        Assert.NotNull(certNodes);
        Assert.True(tsNodes!.Count > 0);
        Assert.Equal(1, certNodes!.Count);
    }

    [Fact]
    public async Task AppendUnsignedCertificateValuesPkcs7_writes_other_certificate_and_round_trips_import()
    {
        using var rsa1 = RSA.Create(2048);
        using var rsa2 = RSA.Create(2048);
        var req1 = new CertificateRequest("CN=p7-a", rsa1, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var req2 = new CertificateRequest("CN=p7-b", rsa2, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var a = req1.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        using var b = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var dfs = new[] { new DataFile(new MemoryStream("p7"u8.ToArray()), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dfs, a, DateTimeOffset.Parse("2026-05-10T10:00:00Z"));
        XadesBesSigner.AppendUnsignedCertificateValuesPkcs7(sig, new[] { a, b });

        XadesSignature xs = sig;
        Assert.Empty(xs.UnsignedEncapsulatedX509Der);
        Assert.Single(xs.UnsignedEncapsulatedPkcs7Der);
        Assert.True(X509Pkcs7CertificateBag.TryImportCertificates(xs.UnsignedEncapsulatedPkcs7Der[0], out var imported));
        Assert.NotNull(imported);
        Assert.Equal(2, imported!.Count);
    }
}
