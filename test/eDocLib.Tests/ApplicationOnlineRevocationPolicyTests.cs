using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using eDocLib;
using eDocLib.Revocation;
using eDocLib.Revocation.Online;
using eDocLib.Revocation.Verify;
using eDocLib.Validation;
using eDocLib.Asic.Xades;
using Org.BouncyCastle.Math;
using Xunit;

namespace eDocLib.Tests;

public class ApplicationOnlineRevocationPolicyTests
{
    private sealed class RecordingFetcher : IRevocationMaterialFetcher
    {
        private readonly RevocationMaterialFetchResult _result;

        public RecordingFetcher(RevocationMaterialFetchResult result) => _result = result;

        public int CallCount { get; private set; }

        public Task<RevocationMaterialFetchResult> FetchAsync(
            X509Certificate2 endEntity,
            X509Certificate2 issuer,
            HttpClient http,
            int maxResponseBytes,
            bool rejectLiteralPrivateAndLoopbackHosts,
            IRevocationDerCache? responseCache,
            bool fetchDeltaCrlViaFreshestCdp,
            CancellationToken cancellationToken)
        {
            CallCount++;
            return Task.FromResult(_result);
        }
    }

    [Fact]
    public async Task UsesApplicationControlledOnlineRevocation_requires_both_online_and_http_client()
    {
        using var http = new HttpClient();
        Assert.False(new SignatureTrustPolicy { RevocationMode = X509RevocationMode.Online }.UsesApplicationControlledOnlineRevocation);
        Assert.False(new SignatureTrustPolicy { RevocationHttpClient = http }.UsesApplicationControlledOnlineRevocation);
        Assert.True(
            new SignatureTrustPolicy { RevocationMode = X509RevocationMode.Online, RevocationHttpClient = http }
                .UsesApplicationControlledOnlineRevocation);
    }

    [Fact]
    public async Task ApplyRevocationMode_sets_NoCheck_when_application_controls_online_revocation()
    {
        using var chain = new X509Chain();
        using var http = new HttpClient();
        var policy = new SignatureTrustPolicy
        {
            RevocationMode = X509RevocationMode.Online,
            RevocationHttpClient = http,
        };
        policy.ApplyRevocationMode(chain.ChainPolicy);
        Assert.Equal(X509RevocationMode.NoCheck, chain.ChainPolicy.RevocationMode);

        var policyPlatform = new SignatureTrustPolicy { RevocationMode = X509RevocationMode.Online };
        policyPlatform.ApplyRevocationMode(chain.ChainPolicy);
        Assert.Equal(X509RevocationMode.Online, chain.ChainPolicy.RevocationMode);
    }

    [Fact]
    public async Task ApplicationOnlineRevocation_TryVerifyIfRequired_uses_injected_material_fetcher()
    {
        var (ocspDer, leaf, issuer) =
            BcOcspRevocationTestData.BuildGoodOcspWithIssuerResponderEmbedded(BigInteger.ValueOf(42_001));
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(issuer);
        Assert.True(chain.Build(leaf));

        using var http = new HttpClient();
        var policy = new SignatureTrustPolicy
        {
            RevocationMode = X509RevocationMode.Online,
            RevocationHttpClient = http,
        };

        var fetcher = new RecordingFetcher(new RevocationMaterialFetchResult([ocspDer], []));
        var outcome = await ApplicationOnlineRevocation.TryVerifyIfRequiredAsync(policy, leaf, chain, fetcher);
        Assert.True(outcome.Ok, outcome.Error);
        Assert.Equal(1, fetcher.CallCount);
        Assert.NotNull(outcome.Fetched);
    }

    [Fact]
    public async Task OnlineRevocationVerifier_TryVerifyFetched_fails_on_empty_material()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=x", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var empty = new RevocationMaterialFetchResult([], []);
        Assert.False(OnlineRevocationVerifier.TryVerifyFetched(cert, empty, new[] { cert }, out var err), err);
        Assert.Contains("no OCSP or CRL", err, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task OnlineRevocationVerifier_accepts_fetched_ocsp_under_strict_responder_pkix_when_embedded_is_ca()
    {
        var (ocspDer, leaf, issuer) =
            BcOcspRevocationTestData.BuildGoodOcspWithIssuerResponderEmbedded(BigInteger.ValueOf(88_801));
        var chain = new[] { leaf, issuer };
        var fetched = new RevocationMaterialFetchResult([ocspDer], []);
        var policyOpts = new SignatureTrustPolicy
        {
            CustomTrustAnchors = new X509Certificate2Collection(issuer),
            StrictEmbeddedOcspValidateResponderCertificateChain = true,
        }.BuildEmbeddedOcspStrictOptions();
        Assert.NotNull(policyOpts);
        Assert.True(OnlineRevocationVerifier.TryVerifyFetched(leaf, fetched, chain, out var err, policyOpts), err);
    }

    [Fact]
    public async Task OnlineRevocationVerifier_rejects_fetched_ocsp_when_dedicated_responder_not_under_signer_anchors()
    {
        var (ocspDer, leaf, issuer) =
            BcOcspRevocationTestData.BuildOcspSignedByDedicatedResponder(BigInteger.ValueOf(88_802));
        var chain = new[] { leaf, issuer };
        var fetched = new RevocationMaterialFetchResult([ocspDer], []);
        var policyOpts = new SignatureTrustPolicy
        {
            CustomTrustAnchors = new X509Certificate2Collection(issuer),
            StrictEmbeddedOcspValidateResponderCertificateChain = true,
        }.BuildEmbeddedOcspStrictOptions();
        Assert.NotNull(policyOpts);
        Assert.False(OnlineRevocationVerifier.TryVerifyFetched(leaf, fetched, chain, out var err, policyOpts), err);
        Assert.Contains("PKIX", err ?? "", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RevocationReport_self_signed_anchor_with_app_online_marks_fetch_skipped_and_succeeds()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=self online", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "self-online"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2024-06-01T12:00:00Z"));

        using var http = new HttpClient();
        var policy = new SignatureTrustPolicy
        {
            ValidateCertificateChain = true,
            RevocationMode = X509RevocationMode.Online,
            RevocationHttpClient = http,
            CustomTrustAnchors = new X509Certificate2Collection(cert),
        };

        var result = await SignatureValidator.ValidateAsync(
            sig,
            new Dictionary<string, byte[]> { ["doc.txt"] = payload },
            policy);

        Assert.True(result.Success, result.Error);
        Assert.True(result.ApplicationOnlineRevocationChecked);
        Assert.True(result.ApplicationOnlineRevocationValid);
        Assert.NotNull(result.Revocation);
        Assert.True(result.Revocation!.ApplicationOnlineFetchSkippedForSelfSignedShortChain);
        Assert.False(result.Revocation.HasNonEmptyOnlineFetchedRevocation);
        Assert.False(result.Revocation.HasEmbeddedRevocationArtifacts);
    }

    [Fact]
    public async Task Edoc_validate_fails_when_online_revocation_client_set_but_leaf_has_no_AIA_or_CDP()
    {
        using var rootRsa = RSA.Create(2048);
        var rootReq = new CertificateRequest("CN=Root", rootRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, false));
        rootReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootReq.PublicKey, false));
        using var root = rootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddYears(10));

        using var subRsa = RSA.Create(2048);
        var subReq = new CertificateRequest("CN=Sub CA", subRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        subReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        subReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, false));
        subReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(subReq.PublicKey, false));
        var subSerial = new byte[8];
        RandomNumberGenerator.Fill(subSerial);
        using var subPub = subReq.Create(root, DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddYears(5), subSerial);
        using var sub = subPub.CopyWithPrivateKey(subRsa);

        using var leafRsa = RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=Leaf", leafRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        var leafSerial = new byte[8];
        RandomNumberGenerator.Fill(leafSerial);
        using var leafPub = leafReq.Create(sub, DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddYears(1), leafSerial);
        using var leaf = leafPub.CopyWithPrivateKey(leafRsa);

        var tslXml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
              <X509Certificate>{Convert.ToBase64String(sub.Export(X509ContentType.Cert))}</X509Certificate>
              <X509Certificate>{Convert.ToBase64String(root.Export(X509ContentType.Cert))}</X509Certificate>
            </TrustServiceStatusList>
            """;

        var tslExtra = TrustedListCertificateParser.ReadCertificates(new MemoryStream(Encoding.UTF8.GetBytes(tslXml)));

        var payload = "online-rev"u8.ToArray();
        var dataFiles = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dataFiles, leaf, DateTimeOffset.Parse("2024-06-01T12:00:00Z"));

        var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
        edoc.AddSignature(sig);

        using var zip = new MemoryStream();
        edoc.Save(zip);
        zip.Position = 0;

        using var http = new HttpClient();
        var policy = new SignatureTrustPolicy
        {
            ValidateCertificateChain = true,
            RevocationMode = X509RevocationMode.Online,
            RevocationHttpClient = http,
            CustomTrustAnchors = new X509Certificate2Collection(root),
            ExtraChainCertificates = tslExtra,
        };

        try
        {
            var report = await EdocValidation.OpenAndValidateAsync(zip, policy);
            Assert.False(report.AllSignaturesValid);
            Assert.Contains("Online revocation", report.Signatures[0].Result.Error ?? "", StringComparison.Ordinal);
            Assert.True(report.Signatures[0].Result.ApplicationOnlineRevocationChecked);
            Assert.False(report.Signatures[0].Result.ApplicationOnlineRevocationValid);
        }
        finally
        {
            foreach (X509Certificate2 c in tslExtra)
            {
                c.Dispose();
            }
        }
    }
}
