using eDocLib.Trust.Tsl;
using Xunit;

namespace eDocLib;

public class NullTrustedListProviderTests
{
    [Fact]
    public async Task GetTrustedListAsync_returns_empty_stream()
    {
        var p = new NullTrustedListProvider();
        using var s = await p.GetTrustedListAsync("LV");
        Assert.Equal(0, s.Length);
    }
}
