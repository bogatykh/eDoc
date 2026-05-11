using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib.Asic.Container;
using eDocLib.Revocation;
using eDocLib.Revocation.Online;
using eDocLib.Revocation.Protocols.Ocsp;
using eDocLib.Revocation.Xades;
using eDocLib.Asic.Xades;
using Org.BouncyCastle.Asn1;
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

public class RevocationClientsTests
{
    [Fact]
    public async Task OcspRequestBuilder_BuildDer_starts_with_sequence_and_non_empty()
    {
        using var rootRsa = RSA.Create(2048);
        var rootReq = new CertificateRequest("CN=Root OCSP", rootRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, false));
        rootReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootReq.PublicKey, false));
        using var root = rootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));

        using var leafRsa = RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=Leaf OCSP", leafRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        var leafSerial = new byte[8];
        RandomNumberGenerator.Fill(leafSerial);
        using var leafPub = leafReq.Create(root, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), leafSerial);
        using var leaf = leafPub.CopyWithPrivateKey(leafRsa);

        var der = OcspRequestBuilder.BuildDer(leaf, root);
        Assert.True(der.Length > 20);
        Assert.Equal(0x30, der[0]);
    }

    [Fact]
    public async Task X509RevocationUriDiscovery_self_signed_without_AIA_returns_no_ocsp()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=no aia", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        Assert.False(X509RevocationUriDiscovery.TryGetOcspHttpUri(cert, out _));
        Assert.Empty(X509RevocationUriDiscovery.GetCrlHttpUris(cert));
    }

    [Fact]
    public async Task X509RevocationUriDiscovery_reads_AIA_and_CDP_from_extensions()
    {
        const string ocspUrl = "http://ocsp.example.test/status";
        const string crlUrl = "http://crl.example.test/root.crl";

        var ocspAd = new DerSequence(
            new DerObjectIdentifier(X509RevocationUriDiscovery.OcspAccessMethodOid),
            new GeneralName(GeneralName.UniformResourceIdentifier, ocspUrl));
        var aiaDer = new DerSequence(ocspAd).GetEncoded();

        var crlGn = new GeneralName(GeneralName.UniformResourceIdentifier, crlUrl);
        var fullName = new GeneralNames(crlGn);
        var dpn = new DistributionPointName(DistributionPointName.FullName, fullName);
        var dp = new DistributionPoint(dpn, null, null);
        var cdpDer = new CrlDistPoint(new[] { dp }).GetEncoded();

        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=ext test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new System.Security.Cryptography.X509Certificates.X509Extension(
            "1.3.6.1.5.5.7.1.1", aiaDer, critical: false));
        req.CertificateExtensions.Add(new System.Security.Cryptography.X509Certificates.X509Extension(
            "2.5.29.31", cdpDer, critical: false));
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        Assert.True(X509RevocationUriDiscovery.TryGetOcspHttpUri(cert, out var u));
        Assert.Equal(ocspUrl, u!.ToString());

        var crls = X509RevocationUriDiscovery.GetCrlHttpUris(cert);
        Assert.Single(crls);
        Assert.Equal(crlUrl, crls[0].ToString());
    }

    [Fact]
    public async Task CrlHttpClient_DownloadAsync_returns_response_body()
    {
        var handler = new StubHttpMessageHandler { ResponseBody = new byte[] { 0x30, 0x01, 0xff } };
        using var http = new HttpClient(handler);
        using var client = new CrlHttpClient(http);
        var bytes = await client.DownloadAsync(new Uri("https://crl.example/crl.pem"));
        Assert.Equal(handler.ResponseBody, bytes);
        Assert.Equal(HttpMethod.Get, handler.LastRequest!.Method);
    }

    [Fact]
    public async Task OcspHttpClient_QueryAsync_posts_ocsp_request()
    {
        var handler = new StubHttpMessageHandler { ResponseBody = new byte[] { 0x30, 0x03, 0x0a, 0x01, 0x00 } };
        using var http = new HttpClient(handler);
        using var client = new OcspHttpClient(http);

        using var rsa = RSA.Create(2048);
        var rootReq = new CertificateRequest("CN=R", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, false));
        using var root = rootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(3));

        using var leafRsa = RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=L", leafRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var leafPub = leafReq.Create(root, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), RandomNumberGenerator.GetBytes(8));
        using var leaf = leafPub.CopyWithPrivateKey(leafRsa);

        var resp = await client.QueryAsync(new Uri("http://ocsp.example/ocsp"), leaf, root);
        Assert.Equal(handler.ResponseBody, resp);
        Assert.Equal(HttpMethod.Post, handler.LastRequest!.Method);
        Assert.Equal("application/ocsp-request", handler.LastContentType);
        Assert.Equal(0x30, handler.LastPostedBody![0]);
    }

    [Fact]
    public async Task OcspResponseReader_reads_successful_transport_status()
    {
        // OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED { successful(0) }, ... }
        var der = new byte[] { 0x30, 0x03, 0x0A, 0x01, 0x00 };
        Assert.True(OcspResponseReader.TryGetTransportStatus(der, out var code));
        Assert.Equal(OcspRespStatus.Successful, code);
        Assert.True(OcspResponseReader.IsTransportSuccessful(der));
    }

    [Fact]
    public async Task OcspResponseReader_rejects_garbage()
    {
        Assert.False(OcspResponseReader.TryGetTransportStatus(new byte[] { 0x01, 0x02 }, out _));
        Assert.False(OcspResponseReader.IsTransportSuccessful(new byte[] { 0xff }));
    }

    [Fact]
    public async Task CertificateRevocationMaterialFetcher_downloads_ocsp_and_first_crl()
    {
        const string ocspUrl = "http://fetch.rev.test/ocsp";
        const string crlUrl = "http://fetch.rev.test/ca.crl";
        var ocspAd = new DerSequence(
            new DerObjectIdentifier(X509RevocationUriDiscovery.OcspAccessMethodOid),
            new GeneralName(GeneralName.UniformResourceIdentifier, ocspUrl));
        var aiaDer = new DerSequence(ocspAd).GetEncoded();
        var crlGn = new GeneralName(GeneralName.UniformResourceIdentifier, crlUrl);
        var dpn = new DistributionPointName(DistributionPointName.FullName, new GeneralNames(crlGn));
        var cdpDer = new CrlDistPoint(new[] { new DistributionPoint(dpn, null, null) }).GetEncoded();

        using var rootRsa = RSA.Create(2048);
        var rootReq = new CertificateRequest("CN=FetchRoot", rootRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, false));
        using var root = rootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));

        using var leafRsa = RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=FetchLeaf", leafRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        leafReq.CertificateExtensions.Add(new System.Security.Cryptography.X509Certificates.X509Extension(
            "1.3.6.1.5.5.7.1.1", aiaDer, critical: false));
        leafReq.CertificateExtensions.Add(new System.Security.Cryptography.X509Certificates.X509Extension(
            "2.5.29.31", cdpDer, critical: false));
        using var leafPub = leafReq.Create(root, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), RandomNumberGenerator.GetBytes(8));
        using var leaf = leafPub.CopyWithPrivateKey(leafRsa);

        var ocspDer = new byte[] { 0x30, 0x03, 0x0A, 0x01, 0x00 };
        var crlDer = new byte[] { 0x30, 0x02, 0x01, 0x01 };
        var route = new RoutingHttpMessageHandler(new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            [ocspUrl] = ocspDer,
            [crlUrl] = crlDer,
        });
        using var http = new HttpClient(route);

        var got = await CertificateRevocationMaterialFetcher.FetchAsync(leaf, root, http);
        Assert.Single(got.OcspResponses);
        Assert.Equal(ocspDer, got.OcspResponses[0]);
        Assert.Single(got.Crls);
        Assert.Equal(crlDer, got.Crls[0]);
    }

    [Fact]
    public async Task X509RevocationUriDiscovery_reads_Freshest_CRL_HTTP_Uris_from_base_CRL()
    {
        const string deltaUrl = "http://delta.example.test/delta.crl";
        var freshestGn = new GeneralName(GeneralName.UniformResourceIdentifier, deltaUrl);
        var freshestDpn = new DistributionPointName(DistributionPointName.FullName, new GeneralNames(freshestGn));
        var freshestDer = new CrlDistPoint(new[] { new DistributionPoint(freshestDpn, null, null) }).GetEncoded();

        var random = new SecureRandom();
        var keyGen = new RsaKeyPairGenerator();
        keyGen.Init(new KeyGenerationParameters(random, 2048));
        var issuerKp = keyGen.GenerateKeyPair();

        var issuerGen = new X509V3CertificateGenerator();
        issuerGen.SetSerialNumber(BigInteger.One);
        var issuerDn = new X509Name("CN=Freshest CRL CA");
        issuerGen.SetIssuerDN(issuerDn);
        issuerGen.SetSubjectDN(issuerDn);
        issuerGen.SetNotBefore(DateTime.UtcNow.AddDays(-2));
        issuerGen.SetNotAfter(DateTime.UtcNow.AddYears(5));
        issuerGen.SetPublicKey(issuerKp.Public);
        issuerGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(0));
        issuerGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));
        issuerGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", issuerKp.Private));

        var crlGen = new X509V2CrlGenerator();
        crlGen.SetIssuerDN(issuerDn);
        crlGen.SetThisUpdate(DateTime.UtcNow.AddHours(-2));
        crlGen.SetNextUpdate(DateTime.UtcNow.AddDays(30));
        crlGen.AddExtension(X509Extensions.FreshestCrl, false, freshestDer);
        var crl = crlGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", issuerKp.Private));

        var uris = X509RevocationUriDiscovery.GetFreshestCrlHttpUris(crl.GetEncoded());
        Assert.Single(uris);
        Assert.Equal(deltaUrl, uris[0].ToString());
    }

    [Fact]
    public async Task CertificateRevocationMaterialFetcher_downloads_delta_after_base_when_freshest_enabled()
    {
        const string ocspUrl = "http://fetch.rev.test/ocsp";
        const string baseCrlUrl = "http://fetch.rev.test/ca.crl";
        const string deltaCrlUrl = "http://fetch.rev.test/delta.crl";
        var ocspAd = new DerSequence(
            new DerObjectIdentifier(X509RevocationUriDiscovery.OcspAccessMethodOid),
            new GeneralName(GeneralName.UniformResourceIdentifier, ocspUrl));
        var aiaDer = new DerSequence(ocspAd).GetEncoded();
        var crlGn = new GeneralName(GeneralName.UniformResourceIdentifier, baseCrlUrl);
        var dpn = new DistributionPointName(DistributionPointName.FullName, new GeneralNames(crlGn));
        var cdpDer = new CrlDistPoint(new[] { new DistributionPoint(dpn, null, null) }).GetEncoded();

        using var rootRsa = RSA.Create(2048);
        var rootReq = new CertificateRequest("CN=FetchRoot", rootRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, false));
        using var root = rootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));

        using var leafRsa = RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=FetchLeaf", leafRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        leafReq.CertificateExtensions.Add(new System.Security.Cryptography.X509Certificates.X509Extension(
            "1.3.6.1.5.5.7.1.1", aiaDer, critical: false));
        leafReq.CertificateExtensions.Add(new System.Security.Cryptography.X509Certificates.X509Extension(
            "2.5.29.31", cdpDer, critical: false));
        using var leafPub = leafReq.Create(root, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), RandomNumberGenerator.GetBytes(8));
        using var leaf = leafPub.CopyWithPrivateKey(leafRsa);

        var deltaGn = new GeneralName(GeneralName.UniformResourceIdentifier, deltaCrlUrl);
        var freshestDpn = new DistributionPointName(DistributionPointName.FullName, new GeneralNames(deltaGn));
        var freshestDer = new CrlDistPoint(new[] { new DistributionPoint(freshestDpn, null, null) }).GetEncoded();

        var parser = new X509CertificateParser();
        var rootBc = parser.ReadCertificate(root.RawData);
        var rootKp = DotNetUtilities.GetKeyPair(root.GetRSAPrivateKey()!);
        var crlGen = new X509V2CrlGenerator();
        crlGen.SetIssuerDN(rootBc.SubjectDN);
        crlGen.SetThisUpdate(DateTime.UtcNow.AddHours(-2));
        crlGen.SetNextUpdate(DateTime.UtcNow.AddDays(30));
        crlGen.AddExtension(X509Extensions.FreshestCrl, false, freshestDer);
        var baseCrlDer = crlGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", rootKp.Private)).GetEncoded();

        var deltaCrlGen = new X509V2CrlGenerator();
        deltaCrlGen.SetIssuerDN(rootBc.SubjectDN);
        deltaCrlGen.SetThisUpdate(DateTime.UtcNow.AddHours(-1));
        deltaCrlGen.SetNextUpdate(DateTime.UtcNow.AddDays(30));
        var deltaCrlDer = deltaCrlGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", rootKp.Private)).GetEncoded();

        var ocspDer = new byte[] { 0x30, 0x03, 0x0A, 0x01, 0x00 };
        var route = new RoutingHttpMessageHandler(new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            [ocspUrl] = ocspDer,
            [baseCrlUrl] = baseCrlDer,
            [deltaCrlUrl] = deltaCrlDer,
        });
        using var http = new HttpClient(route);

        var got = await CertificateRevocationMaterialFetcher.FetchAsync(leaf, root, http, fetchDeltaCrlViaFreshestCdp: true);
        Assert.Single(got.OcspResponses);
        Assert.Equal(ocspDer, got.OcspResponses[0]);
        Assert.Equal(2, got.Crls.Count);
        Assert.Equal(baseCrlDer, got.Crls[0]);
        Assert.Equal(deltaCrlDer, got.Crls[1]);
    }

    [Fact]
    public async Task CertificateRevocationMaterialFetcher_skips_delta_when_freshest_unreachable()
    {
        const string ocspUrl = "http://fetch.rev2.test/ocsp";
        const string baseCrlUrl = "http://fetch.rev2.test/ca.crl";
        const string deltaCrlUrl = "http://fetch.rev2.test/missing-delta.crl";
        var ocspAd = new DerSequence(
            new DerObjectIdentifier(X509RevocationUriDiscovery.OcspAccessMethodOid),
            new GeneralName(GeneralName.UniformResourceIdentifier, ocspUrl));
        var aiaDer = new DerSequence(ocspAd).GetEncoded();
        var crlGn = new GeneralName(GeneralName.UniformResourceIdentifier, baseCrlUrl);
        var dpn = new DistributionPointName(DistributionPointName.FullName, new GeneralNames(crlGn));
        var cdpDer = new CrlDistPoint(new[] { new DistributionPoint(dpn, null, null) }).GetEncoded();

        using var rootRsa = RSA.Create(2048);
        var rootReq = new CertificateRequest("CN=FetchRoot2", rootRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, false));
        using var root = rootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));

        using var leafRsa = RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=FetchLeaf2", leafRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        leafReq.CertificateExtensions.Add(new System.Security.Cryptography.X509Certificates.X509Extension(
            "1.3.6.1.5.5.7.1.1", aiaDer, critical: false));
        leafReq.CertificateExtensions.Add(new System.Security.Cryptography.X509Certificates.X509Extension(
            "2.5.29.31", cdpDer, critical: false));
        using var leafPub = leafReq.Create(root, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), RandomNumberGenerator.GetBytes(8));
        using var leaf = leafPub.CopyWithPrivateKey(leafRsa);

        var deltaGn = new GeneralName(GeneralName.UniformResourceIdentifier, deltaCrlUrl);
        var freshestDpn = new DistributionPointName(DistributionPointName.FullName, new GeneralNames(deltaGn));
        var freshestDer = new CrlDistPoint(new[] { new DistributionPoint(freshestDpn, null, null) }).GetEncoded();

        var parser = new X509CertificateParser();
        var rootBc = parser.ReadCertificate(root.RawData);
        var rootKp = DotNetUtilities.GetKeyPair(root.GetRSAPrivateKey()!);
        var crlGen = new X509V2CrlGenerator();
        crlGen.SetIssuerDN(rootBc.SubjectDN);
        crlGen.SetThisUpdate(DateTime.UtcNow.AddHours(-2));
        crlGen.SetNextUpdate(DateTime.UtcNow.AddDays(30));
        crlGen.AddExtension(X509Extensions.FreshestCrl, false, freshestDer);
        var baseCrlDer = crlGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", rootKp.Private)).GetEncoded();

        var ocspDer = new byte[] { 0x30, 0x03, 0x0A, 0x01, 0x00 };
        var route = new RoutingHttpMessageHandler(new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            [ocspUrl] = ocspDer,
            [baseCrlUrl] = baseCrlDer,
        });
        using var http = new HttpClient(route);

        var got = await CertificateRevocationMaterialFetcher.FetchAsync(leaf, root, http, fetchDeltaCrlViaFreshestCdp: true);
        Assert.Single(got.Crls);
        Assert.Equal(baseCrlDer, got.Crls[0]);
    }

    [Fact]
    public async Task XadesRevocationEmbedding_appends_when_fetch_returns_data()
    {
        const string ocspUrl = "http://embed.rev.test/ocsp";
        const string crlUrl = "http://embed.rev.test/ca.crl";
        var ocspAd = new DerSequence(
            new DerObjectIdentifier(X509RevocationUriDiscovery.OcspAccessMethodOid),
            new GeneralName(GeneralName.UniformResourceIdentifier, ocspUrl));
        var aiaDer = new DerSequence(ocspAd).GetEncoded();
        var crlGn = new GeneralName(GeneralName.UniformResourceIdentifier, crlUrl);
        var dpn = new DistributionPointName(DistributionPointName.FullName, new GeneralNames(crlGn));
        var cdpDer = new CrlDistPoint(new[] { new DistributionPoint(dpn, null, null) }).GetEncoded();

        using var rootRsa = RSA.Create(2048);
        var rootReq = new CertificateRequest("CN=EmbedRoot", rootRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, false));
        using var root = rootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));

        using var leafRsa = RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=EmbedLeaf", leafRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        leafReq.CertificateExtensions.Add(new System.Security.Cryptography.X509Certificates.X509Extension(
            "1.3.6.1.5.5.7.1.1", aiaDer, critical: false));
        leafReq.CertificateExtensions.Add(new System.Security.Cryptography.X509Certificates.X509Extension(
            "2.5.29.31", cdpDer, critical: false));
        using var leafPub = leafReq.Create(root, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), RandomNumberGenerator.GetBytes(8));
        using var leaf = leafPub.CopyWithPrivateKey(leafRsa);

        var ocspDer = new byte[] { 0x30, 0x03, 0x0A, 0x01, 0x00 };
        var crlDer = new byte[] { 0x30, 0x02, 0x01, 0x02 };
        var route = new RoutingHttpMessageHandler(new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            [ocspUrl] = ocspDer,
            [crlUrl] = crlDer,
        });
        using var http = new HttpClient(route);

        var dfs = new[] { new DataFile(new MemoryStream("embed"u8.ToArray()), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dfs, leaf, DateTimeOffset.Parse("2024-11-01T10:00:00Z"));
        var ok = await XadesRevocationEmbedding.TryAppendUnsignedRevocationFromNetworkAsync(sig, leaf, root, http);
        Assert.True(ok);
        Assert.Single(sig.UnsignedEncapsulatedOcspDer);
        Assert.Single(sig.UnsignedEncapsulatedCrlDer);
    }

    private sealed class RoutingHttpMessageHandler : HttpMessageHandler
    {
        private readonly Dictionary<string, byte[]> _routes;

        public RoutingHttpMessageHandler(Dictionary<string, byte[]> routes) => _routes = routes;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var key = request.RequestUri!.AbsoluteUri;
            if (_routes.TryGetValue(key, out var body))
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) });
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }

    private sealed class StubHttpMessageHandler : HttpMessageHandler
    {
        public byte[] ResponseBody { get; init; } = [];
        public HttpRequestMessage? LastRequest { get; private set; }
        public string? LastContentType { get; private set; }
        public byte[]? LastPostedBody { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            LastContentType = request.Content?.Headers.ContentType?.MediaType;
            LastPostedBody = request.Content is null ? [] : await request.Content.ReadAsByteArrayAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(ResponseBody),
            };
        }
    }
}
