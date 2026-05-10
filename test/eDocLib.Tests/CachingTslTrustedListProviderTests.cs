using eDocLib.Trust.Tsl;
using Xunit;

namespace eDocLib.Tests;

public class CachingTslTrustedListProviderTests
{
    private sealed class CountingInner : ITrustedListProvider
    {
        public int CallCount;
        private readonly byte[] _payload;

        public CountingInner(byte[] payload) => _payload = payload;

        public Task<Stream> GetTrustedListAsync(string territory, CancellationToken cancellationToken = default)
        {
            CallCount++;
            return Task.FromResult<Stream>(new MemoryStream(_payload));
        }
    }

    [Fact]
    public async Task Second_call_uses_cache_when_fresh()
    {
        var dir = Path.Combine(Path.GetTempPath(), "edoc-tsl-cache-" + Guid.NewGuid().ToString("N"));
        try
        {
            var payload = "<TrustServiceStatusList />"u8.ToArray();
            var inner = new CountingInner(payload);
            var cache = new CachingTslTrustedListProvider(inner, dir, maxAge: TimeSpan.FromDays(1));

            await using (var s1 = await cache.GetTrustedListAsync("EU"))
            {
                using var r1 = new StreamReader(s1);
                Assert.Contains("TrustServiceStatusList", r1.ReadToEnd(), StringComparison.Ordinal);
            }

            Assert.Equal(1, inner.CallCount);

            await using (var s2 = await cache.GetTrustedListAsync("EU"))
            {
                using var r2 = new StreamReader(s2);
                Assert.Contains("TrustServiceStatusList", r2.ReadToEnd(), StringComparison.Ordinal);
            }

            Assert.Equal(1, inner.CallCount);
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
    public async Task Zero_max_age_refetches_each_time()
    {
        var dir = Path.Combine(Path.GetTempPath(), "edoc-tsl-cache-stale-" + Guid.NewGuid().ToString("N"));
        try
        {
            var inner = new CountingInner("<a/>"u8.ToArray());
            var cache = new CachingTslTrustedListProvider(inner, dir, maxAge: TimeSpan.Zero);

            await using (await cache.GetTrustedListAsync("LV")) { }
            await using (await cache.GetTrustedListAsync("LV")) { }

            Assert.Equal(2, inner.CallCount);
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
    public async Task Stale_cache_file_triggers_refetch_when_max_age_positive()
    {
        var dir = Path.Combine(Path.GetTempPath(), "edoc-tsl-cache-stale-file-" + Guid.NewGuid().ToString("N"));
        try
        {
            var payload = "<TrustServiceStatusList stale=\"0\" />"u8.ToArray();
            var inner = new CountingInner(payload);
            var cache = new CachingTslTrustedListProvider(inner, dir, maxAge: TimeSpan.FromHours(1));

            await using (await cache.GetTrustedListAsync("DE")) { }
            Assert.Equal(1, inner.CallCount);

            var path = Directory.GetFiles(dir, "*.tsl.xml").Single();
            File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddHours(-2));

            await using (await cache.GetTrustedListAsync("DE")) { }
            Assert.Equal(2, inner.CallCount);
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
    public async Task Infinite_max_age_never_refetches()
    {
        var dir = Path.Combine(Path.GetTempPath(), "edoc-tsl-cache-inf-" + Guid.NewGuid().ToString("N"));
        try
        {
            var inner = new CountingInner("<TrustServiceStatusList />"u8.ToArray());
            var cache = new CachingTslTrustedListProvider(inner, dir, maxAge: Timeout.InfiniteTimeSpan);

            await using (await cache.GetTrustedListAsync("EU")) { }
            await using (await cache.GetTrustedListAsync("EU")) { }

            Assert.Equal(1, inner.CallCount);
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
