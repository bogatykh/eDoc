using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace eDocLib.Tests;

/// <summary>Test double: returns queued responses in order and records request URIs.</summary>
internal sealed class QueuedHttpMessageHandler : HttpMessageHandler
{
    private readonly Queue<HttpResponseMessage> _responses = new();
    private readonly List<string> _requestUris = new();

    internal IReadOnlyList<string> RequestUris => _requestUris;

    internal void Enqueue(HttpResponseMessage response) => _responses.Enqueue(response);

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        _requestUris.Add(request.RequestUri!.ToString());
        return Task.FromResult(_responses.Dequeue());
    }
}
