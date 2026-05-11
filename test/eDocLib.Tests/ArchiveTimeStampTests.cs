using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using eDocLib;
using eDocLib.Asic.Container;
using eDocLib.Validation;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

public class ArchiveTimeStampTests
{
    [Fact]
    public async Task ReadEncapsulatedArchiveTimeStamps_empty_without_archive_element()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=a-ts-empty", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "p"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2025-06-01T00:00:00Z"));
        Assert.Empty(sig.UnsignedEncapsulatedArchiveTimeStampDer);
    }

    [Fact]
    public async Task Archive_imprint_round_trip_digest_equals_compute_default_after_strip()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=a-ts-digest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "digest-debug"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2025-06-10T00:00:00Z"));
        var asic = Assert.IsType<AsicSignature>(sig);
        var imprintBeforeAppend = XadesBesSigner.ComputeDefaultArchiveTimestampImprintSha256(asic);

        var tsp = new LocalSha256Rfc3161TimestampProvider();
        XadesBesSigner.AppendArchiveTimeStamp(sig, await tsp.GetTimestampAsync(imprintBeforeAppend));

        var doc = (XmlDocument)sig.GetSignatureOwnerDocument().CloneNode(true);
        var nsm = new XmlNamespaceManager(doc.NameTable);
        nsm.AddNamespace("xades", XadesSignature.XadesNamespaceUrl);
        var archNodes = doc.SelectNodes("//xades:ArchiveTimeStamp", nsm);
        Assert.NotNull(archNodes);
        foreach (XmlNode n in archNodes!)
        {
            n.ParentNode!.RemoveChild(n);
        }

        var digestAfterStrip = XadesBesSigner.ComputeDefaultArchiveTimestampImprintSha256(doc);
        Assert.Equal(imprintBeforeAppend, digestAfterStrip);
    }

    [Fact]
    public async Task AppendArchiveTimeStamp_then_read_and_optional_validate()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=a-ts", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "payload-a"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2025-06-01T00:00:00Z"));

        var tsp = new LocalSha256Rfc3161TimestampProvider();
        var asic = Assert.IsType<AsicSignature>(sig);
        var imprint = XadesBesSigner.ComputeDefaultArchiveTimestampImprintSha256(asic);
        var tokenDer = await tsp.GetTimestampAsync(imprint);

        XadesBesSigner.AppendArchiveTimeStamp(sig, tokenDer, "ArchiveTimeStamp-test");

        Assert.Single(sig.UnsignedEncapsulatedArchiveTimeStampDer);

        var policy = new SignatureTrustPolicy
        {
            ValidateArchiveTimeStampCms = true,
            ValidateArchiveTimeStampChain = true,
            CustomTrustAnchors = new X509Certificate2Collection(LocalSha256Rfc3161TimestampProvider.EmbeddedTsaCertificate),
        };

        XadesSignature xs = sig;
        var result = await SignatureValidator.ValidateAsync(xs, new Dictionary<string, byte[]> { ["doc.txt"] = payload }, policy);
        Assert.True(result.Success);
        Assert.Equal(1, result.ArchiveTimeStampCount);
        Assert.True(result.ArchiveTimeStampsCmsValid);
        Assert.True(result.ArchiveTimeStampsChainValid);
        Assert.True(result.ArchiveTimeStampImprintsValid);
    }

    [Fact]
    public async Task AppendArchiveTimeStamp_wrong_imprint_fails_under_imprint_policy()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=a-ts-bad-imprint", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "payload-bad-imprint"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2025-06-02T00:00:00Z"));

        var tsp = new LocalSha256Rfc3161TimestampProvider();
        var wrongImprint = new byte[32];
        RandomNumberGenerator.Fill(wrongImprint);
        var tokenDer = await tsp.GetTimestampAsync(wrongImprint);
        XadesBesSigner.AppendArchiveTimeStamp(sig, tokenDer);

        var policy = new SignatureTrustPolicy
        {
            ValidateArchiveTimeStampCms = true,
            ValidateArchiveTimeStampChain = true,
            CustomTrustAnchors = new X509Certificate2Collection(LocalSha256Rfc3161TimestampProvider.EmbeddedTsaCertificate),
        };

        XadesSignature xs = sig;
        var result = await SignatureValidator.ValidateAsync(xs, new Dictionary<string, byte[]> { ["doc.txt"] = payload }, policy);
        Assert.False(result.Success);
        Assert.False(result.ArchiveTimeStampImprintsValid);
    }

    [Fact]
    public async Task Two_archive_tokens_imprint_policy_matches_chained_digest_inputs()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=a-ts-chain", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "payload-chain"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2025-06-03T00:00:00Z"));
        var asic = Assert.IsType<AsicSignature>(sig);
        var tsp = new LocalSha256Rfc3161TimestampProvider();

        var d0 = XadesBesSigner.ComputeDefaultArchiveTimestampImprintSha256(asic);
        XadesBesSigner.AppendArchiveTimeStamp(sig, await tsp.GetTimestampAsync(d0), "ATS-1");

        asic = Assert.IsType<AsicSignature>(sig);
        var d1 = XadesBesSigner.ComputeDefaultArchiveTimestampImprintSha256(asic);
        XadesBesSigner.AppendArchiveTimeStamp(sig, await tsp.GetTimestampAsync(d1), "ATS-2");

        var policy = new SignatureTrustPolicy
        {
            ValidateArchiveTimeStampCms = true,
            ValidateArchiveTimeStampChain = true,
            CustomTrustAnchors = new X509Certificate2Collection(LocalSha256Rfc3161TimestampProvider.EmbeddedTsaCertificate),
        };

        XadesSignature xs = sig;
        var result = await SignatureValidator.ValidateAsync(xs, new Dictionary<string, byte[]> { ["doc.txt"] = payload }, policy);
        Assert.True(result.Success);
        Assert.Equal(2, result.ArchiveTimeStampCount);
        Assert.True(result.ArchiveTimeStampImprintsValid);
    }
}
