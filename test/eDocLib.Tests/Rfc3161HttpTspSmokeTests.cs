using System.Security.Cryptography;
using eDocLib.Timestamp;
using Xunit;

namespace eDocLib.Tests;

/// <summary>Optional network smoke: set <c>EDOC_TEST_HTTP_TSP_URL</c> to an RFC 3161 HTTP endpoint (e.g. CI secret).</summary>
public class Rfc3161HttpTspSmokeTests
{
    [Fact]
    public async Task Http_timestamp_provider_round_trip_when_env_configured()
    {
        var url = Environment.GetEnvironmentVariable("EDOC_TEST_HTTP_TSP_URL");
        if (string.IsNullOrWhiteSpace(url))
        {
            return;
        }

        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
        var tsp = new Rfc3161HttpTimestampProvider(new Uri(url.Trim(), UriKind.Absolute), http);
        var imprint = SHA256.HashData("edoc-tsp-probe"u8.ToArray());
        var token = await tsp.GetTimestampAsync(imprint, CancellationToken.None);
        Assert.NotNull(token);
        Assert.NotEmpty(token);
    }
}
