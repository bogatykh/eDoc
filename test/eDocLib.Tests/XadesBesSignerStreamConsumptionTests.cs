using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

/// <summary>
/// <see cref="XadesBesSigner.PrepareSign"/> reads each <see cref="IDataFile.Stream"/> from current position to end;
/// callers must rewind seekable streams between passes (see also <see cref="Edoc.ResetPayloadStreamsIfSeekable"/>).
/// </summary>
public class XadesBesSignerStreamConsumptionTests
{
    [Fact]
    public void Second_prepare_without_rewind_sees_empty_payload_and_differs_from_first()
    {
        var payload = "stream-consume"u8.ToArray();
        var ms = new MemoryStream(payload.ToArray());
        var dfs = new[] { new DataFile(ms, "segment.txt", "text/plain") };

        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=consume", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var publicOnly = new X509Certificate2(cert.Export(X509ContentType.Cert));

        var t = DateTimeOffset.Parse("2026-12-09T11:00:00Z");
        var prep1 = XadesBesSigner.PrepareSign(dfs, publicOnly, t);
        Assert.Equal(payload.Length, ms.Position);

        var prep2 = XadesBesSigner.PrepareSign(dfs, publicOnly, t);
        Assert.NotEqual(prep1.GetSignableBytes(), prep2.GetSignableBytes());

        ms.Position = 0;
        var prep3 = XadesBesSigner.PrepareSign(dfs, publicOnly, t);
        Assert.Equal(prep1.GetSignableBytes(), prep3.GetSignableBytes());
    }
}
