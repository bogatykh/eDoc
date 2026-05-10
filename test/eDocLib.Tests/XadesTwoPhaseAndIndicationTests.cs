using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib.Asic.Container;
using eDocLib.Validation;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

public class XadesTwoPhaseAndIndicationTests
{
    [Fact]
    public void PrepareSign_then_Complete_produces_same_bytes_as_Sign()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=two-phase", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "payload"u8.ToArray();
        var t = DateTimeOffset.Parse("2024-05-05T12:00:00Z");

        var oneShot = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
            cert,
            t,
            signatureId: "S1",
            signedPropertiesId: "SP-1");

        using var ms1 = new MemoryStream();
        oneShot.WriteTo(ms1);

        var publicOnly = new X509Certificate2(cert.Export(X509ContentType.Cert));
        var prep = XadesBesSigner.PrepareSign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
            publicOnly,
            t,
            signatureId: "S1",
            signedPropertiesId: "SP-1");
        Assert.Equal(XadesSignatureAlgorithms.RsaWithSha256, prep.SignatureMethodUri);

        var signable = prep.GetSignableBytes();
        var priv = cert.GetRSAPrivateKey()!;
        var sigBytes = priv.SignData(signable, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var twoPhase = prep.Complete(sigBytes);

        using var ms2 = new MemoryStream();
        twoPhase.WriteTo(ms2);

        Assert.Equal(ms1.ToArray(), ms2.ToArray());

        Assert.True(DetachedSignatureVerifier.TryVerify(twoPhase, new Dictionary<string, byte[]> { ["doc.txt"] = payload }, out var err), err);
    }

    [Fact]
    public void RSA_SHA384_sign_prepare_verify_round_trip()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=rsa-sha384", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "rsa384-payload"u8.ToArray();
        var t = DateTimeOffset.Parse("2024-05-05T12:00:00Z");
        static DataFile Df(byte[] p) => new(new MemoryStream(p.ToArray()), "doc.txt", "text/plain");

        var sig = XadesBesSigner.Sign(new[] { Df(payload) }, cert, t, rsaDigestPreference: XadesRsaDigestPreference.Sha384);
        Assert.Equal(XadesSignatureAlgorithms.RsaWithSha384, sig.SignatureMethod);
        Assert.True(DetachedSignatureVerifier.TryVerify(sig, new Dictionary<string, byte[]> { ["doc.txt"] = payload }, out var err1), err1);

        var publicOnly = new X509Certificate2(cert.Export(X509ContentType.Cert));
        var prep = XadesBesSigner.PrepareSign(new[] { Df(payload) }, publicOnly, t, rsaDigestPreference: XadesRsaDigestPreference.Sha384);
        Assert.Equal(XadesSignatureAlgorithms.RsaWithSha384, prep.SignatureMethodUri);
        var signable = prep.GetSignableBytes();
        var sigBytes = cert.GetRSAPrivateKey()!.SignData(signable, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1);
        var twoPhase = prep.Complete(sigBytes);
        Assert.True(DetachedSignatureVerifier.TryVerify(twoPhase, new Dictionary<string, byte[]> { ["doc.txt"] = payload }, out var err2), err2);
    }

    [Fact]
    public void PrepareSign_then_Complete_ECDSA_P256_matches_Sign_and_verifies()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=ecdsa-p256", ec, HashAlgorithmName.SHA256);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "ec-payload"u8.ToArray();
        var t = DateTimeOffset.Parse("2024-05-05T12:00:00Z");

        var oneShot = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
            cert,
            t,
            signatureId: "S1",
            signedPropertiesId: "SP-1");

        using var ms1 = new MemoryStream();
        oneShot.WriteTo(ms1);

        var publicOnly = new X509Certificate2(cert.Export(X509ContentType.Cert));
        var prep = XadesBesSigner.PrepareSign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") },
            publicOnly,
            t,
            signatureId: "S1",
            signedPropertiesId: "SP-1");
        Assert.Equal(XadesSignatureAlgorithms.EcdsaWithSha256, prep.SignatureMethodUri);
        Assert.True(prep.UsesEcdsaSignatureFormat);

        var signable = prep.GetSignableBytes();
        var priv = cert.GetECDsaPrivateKey()!;
        var sigBytes = priv.SignData(signable, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        var twoPhase = prep.Complete(sigBytes);

        Assert.True(DetachedSignatureVerifier.TryVerify(oneShot, new Dictionary<string, byte[]> { ["doc.txt"] = payload }, out var err1), err1);
        Assert.True(DetachedSignatureVerifier.TryVerify(twoPhase, new Dictionary<string, byte[]> { ["doc.txt"] = payload }, out var err2), err2);
        using (var ms2 = new MemoryStream())
        {
            twoPhase.WriteTo(ms2);
            Assert.NotEqual(ms1.ToArray(), ms2.ToArray());
        }
    }

    [Fact]
    public void ECDSA_P384_sign_and_verify_round_trip()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var req = new CertificateRequest("CN=ecdsa-p384", ec, HashAlgorithmName.SHA256);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "p384"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "f.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2025-01-01T00:00:00Z"));
        Assert.True(DetachedSignatureVerifier.TryVerify(sig, new Dictionary<string, byte[]> { ["f.txt"] = payload }, out var err), err);
        Assert.Equal(XadesSignatureAlgorithms.EcdsaWithSha384, sig.SignatureMethod);
    }

    [Fact]
    public void ECDSA_P521_SHA512_sign_and_verify_round_trip()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP521);
        var req = new CertificateRequest("CN=p521", ec, HashAlgorithmName.SHA512);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = "p521"u8.ToArray();
        var sig = XadesBesSigner.Sign(
            new[] { new DataFile(new MemoryStream(payload.ToArray()), "g.txt", "text/plain") },
            cert,
            DateTimeOffset.Parse("2025-02-01T00:00:00Z"));
        Assert.Equal(XadesSignatureAlgorithms.EcdsaWithSha512, sig.SignatureMethod);
        Assert.True(DetachedSignatureVerifier.TryVerify(sig, new Dictionary<string, byte[]> { ["g.txt"] = payload }, out var err), err);
    }

    [Fact]
    public void SignatureValidationIndication_classifies_outcomes()
    {
        Assert.Equal(
            SignatureValidationIndication.TotalPassed,
            new SignatureValidationResult { Success = true, ReferencesAndSignatureValid = true }.GetIndication());

        Assert.Equal(
            SignatureValidationIndication.TotalFailed,
            new SignatureValidationResult { Success = false, ReferencesAndSignatureValid = false }.GetIndication());

        Assert.Equal(
            SignatureValidationIndication.Indeterminate,
            new SignatureValidationResult
            {
                Success = false,
                ReferencesAndSignatureValid = true,
                Error = "Certificate chain validation failed.",
            }.GetIndication());
    }
}
