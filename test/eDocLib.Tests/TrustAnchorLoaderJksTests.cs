using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib.Trust;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Xunit;

namespace eDocLib.Tests;

public class TrustAnchorLoaderJksTests
{
    [Fact]
    public void TrustAnchorLoader_FromJksFile_trusted_cert_entry_round_trips()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=jks-anchor", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var bcCert = new X509CertificateParser().ReadCertificate(cert.RawData);

        var jks = new JksStore();
        jks.SetCertificateEntry("root", bcCert);

        var path = Path.Combine(Path.GetTempPath(), "edoc-jks-" + Guid.NewGuid().ToString("N") + ".jks");
        try
        {
            using (var fs = File.Create(path))
            {
                jks.Save(fs, "secret-password".AsSpan());
            }

            var anchors = TrustAnchorLoader.FromJksFile(path, "secret-password");
            Assert.Single(anchors);
            Assert.Equal(cert.Thumbprint, anchors[0].Thumbprint, StringComparer.OrdinalIgnoreCase);
        }
        finally
        {
            TryDelete(path);
        }
    }

    [Fact]
    public void TrustAnchorLoader_FromJksFile_null_password_loads_unprotected_store()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=jks-plain", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var bcCert = new X509CertificateParser().ReadCertificate(cert.RawData);
        var jks = new JksStore();
        jks.SetCertificateEntry("a", bcCert);
        var path = Path.Combine(Path.GetTempPath(), "edoc-jks-plain-" + Guid.NewGuid().ToString("N") + ".jks");
        try
        {
            using (var fs = File.Create(path))
            {
                jks.Save(fs, ReadOnlySpan<char>.Empty);
            }

            var anchors = TrustAnchorLoader.FromJksFile(path, storePassword: null);
            Assert.Single(anchors);
            Assert.Equal(cert.Thumbprint, anchors[0].Thumbprint, StringComparer.OrdinalIgnoreCase);
        }
        finally
        {
            TryDelete(path);
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
            // best-effort test cleanup
        }
    }
}
