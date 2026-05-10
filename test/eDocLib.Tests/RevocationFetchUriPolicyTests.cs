using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib.Revocation;
using eDocLib.Revocation.Online;
using Xunit;

namespace eDocLib.Tests;

public class RevocationFetchUriPolicyTests
{
    [Theory]
    [InlineData("http://127.0.0.1/ocsp", true, false)]
    [InlineData("http://10.0.0.1/ocsp", true, false)]
    [InlineData("http://192.168.1.1/ocsp", true, false)]
    [InlineData("http://[::1]/ocsp", true, false)]
    [InlineData("http://ocsp.example/ocsp", true, true)]
    [InlineData("http://127.0.0.1/ocsp", false, true)]
    public void IsAllowed_literal_and_hostname(string uri, bool reject, bool expectAllowed)
    {
        var u = new Uri(uri);
        var allowed = RevocationFetchUriPolicy.IsAllowed(u, reject, out var err);
        Assert.Equal(expectAllowed, allowed);
        if (!expectAllowed)
        {
            Assert.NotNull(err);
        }
    }

    [Fact]
    public void CertificateRevocationMaterialFetcher_rejects_loopback_ocsp_when_configured()
    {
        const string ocspUrl = "http://127.0.0.1/ocsp";
        var ocspAd = new Org.BouncyCastle.Asn1.DerSequence(
            new Org.BouncyCastle.Asn1.DerObjectIdentifier(X509RevocationUriDiscovery.OcspAccessMethodOid),
            new Org.BouncyCastle.Asn1.X509.GeneralName(
                Org.BouncyCastle.Asn1.X509.GeneralName.UniformResourceIdentifier,
                ocspUrl));
        var aiaDer = new Org.BouncyCastle.Asn1.DerSequence(ocspAd).GetEncoded();

        using var rootRsa = RSA.Create(2048);
        var rootReq = new CertificateRequest("CN=PolRoot", rootRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, false));
        using var root = rootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));

        using var leafRsa = RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=PolLeaf", leafRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        leafReq.CertificateExtensions.Add(new X509Extension("1.3.6.1.5.5.7.1.1", aiaDer, critical: false));
        using var leafPub = leafReq.Create(root, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), RandomNumberGenerator.GetBytes(8));
        using var leaf = leafPub.CopyWithPrivateKey(leafRsa);

        using var http = new HttpClient();
        var ex = Assert.Throws<InvalidOperationException>(() =>
            CertificateRevocationMaterialFetcher.FetchAsync(leaf, root, http, rejectLiteralPrivateAndLoopbackHosts: true)
                .GetAwaiter()
                .GetResult());
        Assert.Contains("not permitted", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}
