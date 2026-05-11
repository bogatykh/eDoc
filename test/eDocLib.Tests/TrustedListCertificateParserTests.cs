using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using eDocLib.Trust.Tsl;
using eDocLib.Validation;
using Xunit;

namespace eDocLib.Tests;

public class TrustedListCertificateParserTests
{
    [Fact]
    public async Task ReadCertificates_extracts_unique_certs_from_tsl_xml()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=TSL parser test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var der = cert.Export(X509ContentType.Cert);
        var b64 = Convert.ToBase64String(der);
        var xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
              <X509Certificate>{b64}</X509Certificate>
              <X509Certificate>{b64}</X509Certificate>
            </TrustServiceStatusList>
            """;
        using var ms = new MemoryStream(Encoding.UTF8.GetBytes(xml));
        var col = TrustedListCertificateParser.ReadCertificates(ms);
        try
        {
            Assert.Single(col);
            Assert.Equal(cert.Thumbprint, col[0].Thumbprint, StringComparer.OrdinalIgnoreCase);
        }
        finally
        {
            foreach (X509Certificate2 c in col)
                c.Dispose();
        }
    }

    [Fact]
    public async Task TrustedListCertificates_LoadCertificatesAsync_delegates_to_parser()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=provider test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var der = cert.Export(X509ContentType.Cert);
        var xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
              <X509Certificate>{Convert.ToBase64String(der)}</X509Certificate>
            </TrustServiceStatusList>
            """;
        ITrustedListProvider p = new BytesTrustedListProvider(Encoding.UTF8.GetBytes(xml));
        var col = await TrustedListCertificates.LoadCertificatesAsync(p, "EU");
        try
        {
            Assert.Single(col);
            Assert.Equal(cert.Thumbprint, col[0].Thumbprint, StringComparer.OrdinalIgnoreCase);
        }
        finally
        {
            foreach (X509Certificate2 c in col)
                c.Dispose();
        }
    }

    private sealed class BytesTrustedListProvider : ITrustedListProvider
    {
        private readonly byte[] _bytes;
        public BytesTrustedListProvider(byte[] bytes) => _bytes = bytes;
        public Task<Stream> GetTrustedListAsync(string territory, CancellationToken cancellationToken = default) =>
            Task.FromResult<Stream>(new MemoryStream(_bytes));
    }
}
