using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib.Revocation;
using eDocLib.Revocation.Online;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Xunit;

namespace eDocLib.Tests;

public class RevocationDerCacheTests
{
    private sealed class CountingRouteHandler : HttpMessageHandler
    {
        private readonly Dictionary<string, byte[]> _routes;

        public int SendCount;

        public CountingRouteHandler(Dictionary<string, byte[]> routes) => _routes = routes;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref SendCount);
            var key = request.RequestUri!.AbsoluteUri;
            if (_routes.TryGetValue(key, out var body))
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) });
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }

    [Fact]
    public async Task DirectoryRevocationDerCache_round_trips()
    {
        var dir = Path.Combine(Path.GetTempPath(), "edoc-rev-der-" + Guid.NewGuid().ToString("N"));
        try
        {
            var cache = new DirectoryRevocationDerCache(dir);
            var der = new byte[] { 1, 2, 3 };
            await cache.SetAsync("k1", der);
            var got = await cache.TryGetAsync("k1");
            Assert.Equal(der, got);
        }
        finally
        {
            if (Directory.Exists(dir))
            {
                Directory.Delete(dir, recursive: true);
            }
        }
    }

    [Fact]
    public async Task DirectoryRevocationDerCache_MaxEntryAge_expires_and_deletes_on_read()
    {
        var dir = Path.Combine(Path.GetTempPath(), "edoc-rev-exp-" + Guid.NewGuid().ToString("N"));
        try
        {
            var opts = new RevocationDerCacheDirectoryOptions { MaxEntryAge = TimeSpan.FromHours(1) };
            var cache = new DirectoryRevocationDerCache(dir, opts);
            await cache.SetAsync("old-key", new byte[] { 9 });
            var path = Directory.GetFiles(dir, "*.der").Single();
            File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddHours(-2));
            Assert.Null(await cache.TryGetAsync("old-key"));
            Assert.False(File.Exists(path));
        }
        finally
        {
            if (Directory.Exists(dir))
            {
                Directory.Delete(dir, recursive: true);
            }
        }
    }

    [Fact]
    public async Task DirectoryRevocationDerCache_rejects_non_positive_capacity_options()
    {
        var dir = Path.Combine(Path.GetTempPath(), "edoc-rev-cap-bad-" + Guid.NewGuid().ToString("N"));
        try
        {
            Assert.Throws<ArgumentOutOfRangeException>(
                () => new DirectoryRevocationDerCache(dir, new RevocationDerCacheDirectoryOptions { MaxEntryCount = 0 }));
            Assert.Throws<ArgumentOutOfRangeException>(
                () => new DirectoryRevocationDerCache(dir, new RevocationDerCacheDirectoryOptions { MaxTotalBytes = 0 }));
        }
        finally
        {
            if (Directory.Exists(dir))
            {
                Directory.Delete(dir, recursive: true);
            }
        }
    }

    [Fact]
    public async Task DirectoryRevocationDerCache_MaxEntryCount_evicts_oldest_after_set()
    {
        var dir = Path.Combine(Path.GetTempPath(), "edoc-rev-maxc-" + Guid.NewGuid().ToString("N"));
        try
        {
            var opts = new RevocationDerCacheDirectoryOptions { MaxEntryCount = 2 };
            var cache = new DirectoryRevocationDerCache(dir, opts);
            await cache.SetAsync("k1", new byte[] { 1 });
            await cache.SetAsync("k2", new byte[] { 2 });
            var pathK1 = Directory.GetFiles(dir, "*.der").Single(f => File.ReadAllBytes(f).AsSpan().SequenceEqual(new byte[] { 1 }));
            File.SetLastWriteTimeUtc(pathK1, DateTime.UtcNow.AddHours(-2));
            await cache.SetAsync("k3", new byte[] { 3 });
            Assert.Null(await cache.TryGetAsync("k1"));
            Assert.Equal(new byte[] { 2 }, await cache.TryGetAsync("k2"));
            Assert.Equal(new byte[] { 3 }, await cache.TryGetAsync("k3"));
            Assert.Equal(2, Directory.GetFiles(dir, "*.der").Length);
        }
        finally
        {
            if (Directory.Exists(dir))
            {
                Directory.Delete(dir, recursive: true);
            }
        }
    }

    [Fact]
    public async Task DirectoryRevocationDerCache_MaxTotalBytes_evicts_oldest_after_set()
    {
        var dir = Path.Combine(Path.GetTempPath(), "edoc-rev-maxb-" + Guid.NewGuid().ToString("N"));
        try
        {
            var opts = new RevocationDerCacheDirectoryOptions { MaxTotalBytes = 80 };
            var cache = new DirectoryRevocationDerCache(dir, opts);
            await cache.SetAsync("a", new byte[50]);
            var pathA = Assert.Single(Directory.GetFiles(dir, "*.der"));
            File.SetLastWriteTimeUtc(pathA, DateTime.UtcNow.AddHours(-2));
            await cache.SetAsync("b", new byte[50]);
            Assert.Null(await cache.TryGetAsync("a"));
            Assert.Equal(new byte[50], await cache.TryGetAsync("b"));
            var pathB = Assert.Single(Directory.GetFiles(dir, "*.der"));
            File.SetLastWriteTimeUtc(pathB, DateTime.UtcNow.AddHours(-2));
            await cache.SetAsync("c", new byte[50]);
            Assert.Null(await cache.TryGetAsync("a"));
            Assert.Null(await cache.TryGetAsync("b"));
            Assert.Equal(new byte[50], await cache.TryGetAsync("c"));
            Assert.True(Directory.GetFiles(dir, "*.der").Sum(f => new FileInfo(f).Length) <= 80);
        }
        finally
        {
            if (Directory.Exists(dir))
            {
                Directory.Delete(dir, recursive: true);
            }
        }
    }

    [Fact]
    public async Task DirectoryRevocationDerCache_PurgeExpiredEntriesAsync_enforces_MaxEntryCount_on_existing_directory()
    {
        var dir = Path.Combine(Path.GetTempPath(), "edoc-rev-purge-cap-" + Guid.NewGuid().ToString("N"));
        try
        {
            var loose = new DirectoryRevocationDerCache(dir, new RevocationDerCacheDirectoryOptions { MaxEntryCount = 3 });
            await loose.SetAsync("x", new byte[] { 1 });
            await loose.SetAsync("y", new byte[] { 2 });
            await loose.SetAsync("z", new byte[] { 3 });

            // Eviction order is LastWriteTimeUtc (then path). On Windows three rapid writes often share one tick,
            // so tie-break is filename — not "last SetAsync wins". Pin ages like the other cache tests.
            var pathX = Directory.GetFiles(dir, "*.der").Single(f => File.ReadAllBytes(f).AsSpan().SequenceEqual(new byte[] { 1 }));
            var pathY = Directory.GetFiles(dir, "*.der").Single(f => File.ReadAllBytes(f).AsSpan().SequenceEqual(new byte[] { 2 }));
            var pathZ = Directory.GetFiles(dir, "*.der").Single(f => File.ReadAllBytes(f).AsSpan().SequenceEqual(new byte[] { 3 }));
            File.SetLastWriteTimeUtc(pathX, DateTime.UtcNow.AddHours(-2));
            File.SetLastWriteTimeUtc(pathY, DateTime.UtcNow.AddHours(-1));
            File.SetLastWriteTimeUtc(pathZ, DateTime.UtcNow);

            var strict = new DirectoryRevocationDerCache(dir, new RevocationDerCacheDirectoryOptions { MaxEntryCount = 1 });
            await strict.PurgeExpiredEntriesAsync();
            Assert.Single(Directory.GetFiles(dir, "*.der"));
            Assert.Null(await strict.TryGetAsync("x"));
            Assert.Null(await strict.TryGetAsync("y"));
            Assert.Equal(new byte[] { 3 }, await strict.TryGetAsync("z"));
        }
        finally
        {
            if (Directory.Exists(dir))
            {
                Directory.Delete(dir, recursive: true);
            }
        }
    }

    [Fact]
    public async Task DirectoryRevocationDerCache_PurgeExpiredEntriesAsync_removes_stale_files()
    {
        var dir = Path.Combine(Path.GetTempPath(), "edoc-rev-purge-" + Guid.NewGuid().ToString("N"));
        try
        {
            var opts = new RevocationDerCacheDirectoryOptions { MaxEntryAge = TimeSpan.FromMinutes(30) };
            var cache = new DirectoryRevocationDerCache(dir, opts);
            await cache.SetAsync("stale", new byte[] { 1 });
            var path = Directory.GetFiles(dir, "*.der").Single();
            File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddHours(-1));
            await cache.PurgeExpiredEntriesAsync();
            Assert.False(File.Exists(path));
        }
        finally
        {
            if (Directory.Exists(dir))
            {
                Directory.Delete(dir, recursive: true);
            }
        }
    }

    [Fact]
    public async Task FetchAsync_second_call_hits_cache_without_http()
    {
        const string ocspUrl = "http://cache.rev.test/ocsp";
        const string crlUrl = "http://cache.rev.test/ca.crl";
        var ocspAd = new DerSequence(
            new DerObjectIdentifier(X509RevocationUriDiscovery.OcspAccessMethodOid),
            new GeneralName(GeneralName.UniformResourceIdentifier, ocspUrl));
        var aiaDer = new DerSequence(ocspAd).GetEncoded();
        var crlGn = new GeneralName(GeneralName.UniformResourceIdentifier, crlUrl);
        var dpn = new DistributionPointName(DistributionPointName.FullName, new GeneralNames(crlGn));
        var cdpDer = new CrlDistPoint(new[] { new DistributionPoint(dpn, null, null) }).GetEncoded();

        using var rootRsa = RSA.Create(2048);
        var rootReq = new CertificateRequest("CN=CacheRoot", rootRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, false));
        using var root = rootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));

        using var leafRsa = RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=CacheLeaf", leafRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        leafReq.CertificateExtensions.Add(new System.Security.Cryptography.X509Certificates.X509Extension(
            "1.3.6.1.5.5.7.1.1", aiaDer, critical: false));
        leafReq.CertificateExtensions.Add(new System.Security.Cryptography.X509Certificates.X509Extension(
            "2.5.29.31", cdpDer, critical: false));
        using var leafPub = leafReq.Create(root, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), RandomNumberGenerator.GetBytes(8));
        using var leaf = leafPub.CopyWithPrivateKey(leafRsa);

        var ocspDer = new byte[] { 0x30, 0x03, 0x0A, 0x01, 0x00 };
        var crlDer = new byte[] { 0x30, 0x02, 0x01, 0x07 };
        var routes = new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            [ocspUrl] = ocspDer,
            [crlUrl] = crlDer,
        };
        var handler = new CountingRouteHandler(routes);
        using var http = new HttpClient(handler);

        var dir = Path.Combine(Path.GetTempPath(), "edoc-fetch-cache-" + Guid.NewGuid().ToString("N"));
        try
        {
            var disk = new DirectoryRevocationDerCache(dir);
            var a = await CertificateRevocationMaterialFetcher.FetchAsync(leaf, root, http, responseCache: disk);
            Assert.Equal(2, handler.SendCount);
            var b = await CertificateRevocationMaterialFetcher.FetchAsync(leaf, root, http, responseCache: disk);
            Assert.Equal(2, handler.SendCount);
            Assert.Equal(a.OcspResponses[0], b.OcspResponses[0]);
            Assert.Equal(a.Crls[0], b.Crls[0]);
        }
        finally
        {
            if (Directory.Exists(dir))
            {
                Directory.Delete(dir, recursive: true);
            }
        }
    }

    [Fact]
    public async Task DirectoryRevocationDerCache_parallel_writes_distinct_keys_round_trip()
    {
        var dir = Path.Combine(Path.GetTempPath(), "edoc-rev-conc-" + Guid.NewGuid().ToString("N"));
        try
        {
            var cache = new DirectoryRevocationDerCache(dir);
            var tasks = Enumerable.Range(0, 48).Select(i => cache.SetAsync($"ocsp-{i}", new[] { (byte)i })).ToArray();
            await Task.WhenAll(tasks);
            for (var i = 0; i < 48; i++)
            {
                var got = await cache.TryGetAsync($"ocsp-{i}");
                Assert.Equal(new[] { (byte)i }, got);
            }
        }
        finally
        {
            if (Directory.Exists(dir))
            {
                Directory.Delete(dir, recursive: true);
            }
        }
    }
}
