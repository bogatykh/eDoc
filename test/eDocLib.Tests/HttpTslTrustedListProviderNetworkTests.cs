using System.Text;
using eDocLib.Trust.Tsl;
using eDocLib.Validation;
using Xunit;

namespace eDocLib.Tests;

public class HttpTslTrustedListProviderNetworkTests
{
    /// <summary>
    /// Set <c>EDOC_TEST_TSL_NETWORK</c> to run a live HTTPS fetch of the EU LOTL. No-op when unset.
    /// </summary>
    [Fact]
    public async Task Optional_env_fetches_EU_LOTL_xml()
    {
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("EDOC_TEST_TSL_NETWORK")))
            return;

        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
        var p = new HttpTslTrustedListProvider(http);
        await using var s = await p.GetTrustedListAsync("EU");
        var xml = await new StreamReader(s, Encoding.UTF8).ReadToEndAsync();
        Assert.Contains("TrustServiceStatusList", xml, StringComparison.Ordinal);
        Assert.Contains("EUlistofthelists", xml, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Optional_env_EU_LOTL_xml_dsig_verifies()
    {
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("EDOC_TEST_TSL_NETWORK")))
            return;

        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
        var p = new HttpTslTrustedListProvider(http);
        await using var s = await p.GetTrustedListAsync("EU");
        Assert.True(TrustedListXmlSignatureVerifier.TryVerify(s, out var err), err);
    }
}
