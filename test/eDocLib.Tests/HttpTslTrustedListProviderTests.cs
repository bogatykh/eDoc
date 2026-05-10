using System.Net;
using System.Text;
using eDocLib.Trust.Tsl;
using Xunit;

namespace eDocLib.Tests;

public class HttpTslTrustedListProviderTests
{
    private sealed class QueueHandler : HttpMessageHandler
    {
        internal List<string> RequestUris { get; } = new();
        private readonly Queue<HttpResponseMessage> _responses = new();

        public void Enqueue(HttpResponseMessage response) => _responses.Enqueue(response);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestUris.Add(request.RequestUri!.ToString());
            return Task.FromResult(_responses.Dequeue());
        }
    }

    [Fact]
    public async Task GetTrustedListAsync_EU_single_direct_get()
    {
        var handler = new QueueHandler();
        handler.Enqueue(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("<lotl/>", Encoding.UTF8, "application/xml"),
        });
        var http = new HttpClient(handler);
        var p = new HttpTslTrustedListProvider(http);
        await using var s = await p.GetTrustedListAsync("EU");
        using var r = new StreamReader(s);
        Assert.Equal("<lotl/>", r.ReadToEnd());
        Assert.Single(handler.RequestUris);
        Assert.Equal(TslPublicationUris.EuListOfTrustedLists, handler.RequestUris[0]);
    }

    [Fact]
    public async Task GetTrustedListAsync_DE_resolves_via_EU_LOTL_pointers()
    {
        const string minimalLotl = """
            <?xml version="1.0" encoding="UTF-8"?>
            <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
              <SchemeInformation>
                <OtherTSLPointers>
                  <OtherTSLPointer>
                    <TSLLocation>https://national.example/de-tsl.xml</TSLLocation>
                    <AdditionalInformation>
                      <OtherInformation>
                        <SchemeTerritory>DE</SchemeTerritory>
                      </OtherInformation>
                    </AdditionalInformation>
                  </OtherTSLPointer>
                </OtherTSLPointers>
              </SchemeInformation>
            </TrustServiceStatusList>
            """;
        var handler = new QueueHandler();
        handler.Enqueue(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(minimalLotl, Encoding.UTF8, "application/xml"),
        });
        handler.Enqueue(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("<de/>", Encoding.UTF8, "application/xml"),
        });
        var http = new HttpClient(handler);
        var p = new HttpTslTrustedListProvider(http);
        await using var s = await p.GetTrustedListAsync("DE");
        using var r = new StreamReader(s);
        Assert.Equal("<de/>", r.ReadToEnd());
        Assert.Equal(2, handler.RequestUris.Count);
        Assert.Equal(TslPublicationUris.EuListOfTrustedLists, handler.RequestUris[0]);
        Assert.Equal("https://national.example/de-tsl.xml", handler.RequestUris[1]);
    }

    [Fact]
    public async Task GetTrustedListAsync_LV_hits_latvia_national_tsl_uri()
    {
        var handler = new QueueHandler();
        handler.Enqueue(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("<national/>", Encoding.UTF8, "application/xml"),
        });
        var http = new HttpClient(handler);
        var p = new HttpTslTrustedListProvider(http);
        await using var s = await p.GetTrustedListAsync("LV");
        using var r = new StreamReader(s);
        Assert.Equal("<national/>", r.ReadToEnd());
        Assert.Single(handler.RequestUris);
        Assert.Equal(TslPublicationUris.LatviaNationalTrustedList, handler.RequestUris[0]);
    }

    [Fact]
    public async Task GetTrustedListAsync_with_relay_prefix_encodes_target_in_query()
    {
        var handler = new QueueHandler();
        handler.Enqueue(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("<x/>", Encoding.UTF8, "application/xml"),
        });
        var http = new HttpClient(handler);
        var p = new HttpTslTrustedListProvider(http, "https://relay.example/fetch?uri=");
        await using var stream = await p.GetTrustedListAsync("EU");
        Assert.NotNull(stream);
        Assert.StartsWith("https://relay.example/fetch?uri=https%3A%2F%2Fec.europa.eu", handler.RequestUris[0], StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetTrustedListAsync_absolute_https_passed_through()
    {
        var handler = new QueueHandler();
        handler.Enqueue(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("ok", Encoding.UTF8, "text/plain"),
        });
        var http = new HttpClient(handler);
        var p = new HttpTslTrustedListProvider(http);
        await using var s = await p.GetTrustedListAsync("https://custom.example/list.xml");
        using var r = new StreamReader(s);
        Assert.Equal("ok", r.ReadToEnd());
        Assert.Equal("https://custom.example/list.xml", handler.RequestUris[0]);
    }
}
