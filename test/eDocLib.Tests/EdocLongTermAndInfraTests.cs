using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using eDocLib;
using eDocLib.Timestamp;
using eDocLib.Trust;
using eDocLib.Validation;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

public class EdocLongTermAndInfraTests
{
    [Fact]
    public async Task AppendUnsignedLongTermMaterial_certificates_only()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=ltm", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var dfs = new[] { new DataFile(new MemoryStream("q"u8.ToArray()), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2024-10-01T12:00:00Z"));
        XadesBesSigner.AppendUnsignedLongTermMaterial(sig, new[] { cert });
        Assert.Single(sig.UnsignedEncapsulatedX509Der);
    }

    [Fact]
    public async Task EdocLongTermSigningJob_embeds_cert_and_crl_on_container()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=lt-job", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "lt-payload"u8.ToArray();
        var edoc = Edoc.CreateNew();
        edoc.AddDataObject(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
        var job = new EdocLongTermSigningJob(edoc, cert, DateTimeOffset.Parse("2024-10-02T12:00:00Z"))
        {
            CrlDerBlobs = new[] { new byte[] { 0xde, 0xad } },
        };
        var prep = job.Prepare();
        var signable = prep.GetSignableBytes();
        var sigBytes = cert.GetRSAPrivateKey()!.SignData(signable, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        job.CompleteWithEmbeddedMaterial(prep, sigBytes);
        var info = edoc.GetSignature(0);
        Assert.Single(info.UnsignedCertificateValuesDer);
        Assert.Single(info.UnsignedCrlsDer);
    }

    [Fact]
    public async Task EdocLongTermSigningJob_RsaDigestPreference_flows_to_PrepareSign()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=lt-rsa384", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var edoc = Edoc.CreateNew();
        edoc.AddDataObject(new MemoryStream("x"u8.ToArray()), "doc.txt", "text/plain");
        var job = new EdocLongTermSigningJob(edoc, cert, DateTimeOffset.Parse("2025-03-01T12:00:00Z"))
        {
            Xades = { RsaDigestPreference = XadesRsaDigestPreference.Sha384 },
        };
        var prep = job.Prepare();
        Assert.Equal(XadesSignatureAlgorithms.RsaWithSha384, prep.SignatureMethodUri);
        var sigBytes = cert.GetRSAPrivateKey()!.SignData(
            prep.GetSignableBytes(),
            prep.SignedInfoHashAlgorithm,
            RSASignaturePadding.Pkcs1);
        job.CompleteWithEmbeddedMaterial(prep, sigBytes);
        Assert.Equal(1, edoc.SignatureCount);
    }

    [Fact]
    public async Task EdocLongTermSigningJob_timestamp_after_lt_material()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=lt-ts", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var edoc = Edoc.CreateNew();
        edoc.AddDataObject(new MemoryStream("ts"u8.ToArray()), "doc.txt", "text/plain");
        var tsp = new LocalSha256Rfc3161TimestampProvider();
        var job = new EdocLongTermSigningJob(edoc, cert, DateTimeOffset.Parse("2024-10-03T12:00:00Z"))
        {
            CrlDerBlobs = new[] { new byte[] { 0x01, 0x02 } },
        };
        var prep = job.Prepare();
        var sigBytes = cert.GetRSAPrivateKey()!.SignData(prep.GetSignableBytes(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        await job.CompleteWithEmbeddedMaterialAndTimestampAsync(prep, sigBytes, tsp);
        var info = edoc.GetSignature(0);
        Assert.NotEmpty(info.EncapsulatedTimeStampDer);
        Assert.Single(info.UnsignedCrlsDer);
    }

    [Fact]
    public async Task TimestampResponderRegistry_end_entity_route()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=tsr", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var reg = new TimestampResponderRegistry();
        var uri = new Uri("https://tsa.example.invalid/rfc3161");
        reg.RegisterByEndEntityThumbprint(cert.Thumbprint, uri);
        Assert.True(reg.TryGetResponderUri(cert, out var got));
        Assert.Equal(uri, got);
    }

    [Fact]
    public async Task TimestampResponderRegistry_TryCreateHttpProvider_returns_disposable_provider()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=tsr-http", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var reg = new TimestampResponderRegistry();
        reg.RegisterByEndEntityThumbprint(cert.Thumbprint, new Uri("https://tsa.example.invalid/rfc3161"));
        Assert.True(reg.TryCreateHttpProvider(cert, out var provider));
        Assert.NotNull(provider);
        provider.Dispose();
    }

    [Fact]
    public async Task TrustAnchorLoader_pem_two_certs()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=a", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var c1 = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        using var rsa2 = RSA.Create(2048);
        var req2 = new CertificateRequest("CN=b", rsa2, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var c2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var pem = new StringBuilder();
        pem.AppendLine(PemEncoding.WriteString("CERTIFICATE", c1.RawData));
        pem.AppendLine(PemEncoding.WriteString("CERTIFICATE", c2.RawData));
        var coll = TrustAnchorLoader.FromPem(pem.ToString());
        Assert.Equal(2, coll.Count);
    }

    [Fact]
    public async Task Edoc_Save_with_preflight_throws_on_bad_signature()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=bad", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var edoc = Edoc.CreateNew();
        edoc.AddDataObject(new MemoryStream("ok"u8.ToArray()), "doc.txt", "text/plain");
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream("other"u8.ToArray()), "doc.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2024-11-01T10:00:00Z"));
        edoc.AddSignature(sig);
        using var ms = new MemoryStream();
        await Assert.ThrowsAsync<InvalidOperationException>(
                async () => await edoc.SaveAsync(ms, validateSignaturesFirst: true))
            ;
    }

    [Fact]
    public async Task EdocLongTermSigningJob_pkcs7_embedded_chain_feeds_signer_pkix_when_anchor_is_root_only()
    {
        using var rootKey = RSA.Create(2048);
        var rootReq = new CertificateRequest("CN=lt-p7-root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, false));
        rootReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootReq.PublicKey, false));
        using var root = rootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-3), DateTimeOffset.UtcNow.AddYears(10));

        using var imKey = RSA.Create(2048);
        var imReq = new CertificateRequest("CN=lt-p7-im", imKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        imReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        imReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, false));
        imReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(imReq.PublicKey, false));
        var imSerial = new byte[9];
        RandomNumberGenerator.Fill(imSerial);
        using var intermediatePub = imReq.Create(root, DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddYears(5), imSerial);
        using var intermediate = intermediatePub.CopyWithPrivateKey(imKey);

        using var leafKey = RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=lt-p7-leaf", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        var leafSerial = new byte[9];
        RandomNumberGenerator.Fill(leafSerial);
        using var leafPub = leafReq.Create(intermediate, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), leafSerial);
        using var leaf = leafPub.CopyWithPrivateKey(leafKey);

        var edoc = Edoc.CreateNew();
        edoc.AddDataObject(new MemoryStream("pkcs7-lt"u8.ToArray()), "doc.txt", "text/plain");
        var job = new EdocLongTermSigningJob(edoc, leaf, DateTimeOffset.Parse("2026-05-10T14:00:00Z"))
        {
            CertificateValuesFormat = CertificateValuesWireFormat.Pkcs7,
            CaCertificatesToEmbed = new[] { intermediate },
        };
        var prep = job.Prepare();
        var sigBytes = leaf.GetRSAPrivateKey()!.SignData(prep.GetSignableBytes(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        job.CompleteWithEmbeddedMaterial(prep, sigBytes);

        var info = edoc.GetSignature(0);
        Assert.Empty(info.UnsignedCertificateValuesDer);
        Assert.Single(info.UnsignedCertificateValuesPkcs7Der);

        using var zip = new MemoryStream();
        edoc.Save(zip);
        zip.Position = 0;

        var anchors = new X509Certificate2Collection(root);
        var okPolicy = new SignatureTrustPolicy
        {
            ValidateCertificateChain = true,
            RevocationMode = X509RevocationMode.NoCheck,
            CustomTrustAnchors = anchors,
            IncludeUnsignedCertificateValuesInSignerChain = true,
        };
        var okReport = await EdocValidation.OpenAndValidateAsync(zip, okPolicy);
        Assert.True(okReport.AllSignaturesValid, okReport.Signatures[0].Result.Error);

        zip.Position = 0;
        var failPolicy = new SignatureTrustPolicy
        {
            ValidateCertificateChain = true,
            RevocationMode = X509RevocationMode.NoCheck,
            CustomTrustAnchors = anchors,
            IncludeUnsignedCertificateValuesInSignerChain = false,
        };
        var failReport = await EdocValidation.OpenAndValidateAsync(zip, failPolicy);
        Assert.False(failReport.AllSignaturesValid);
    }
}
