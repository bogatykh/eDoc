namespace eDocLib.Internal;

/// <summary>Shared optional ownership when callers omit a shared <see cref="HttpClient"/>.</summary>
internal static class HttpClientOwnership
{
    /// <summary>Returns a provided client without ownership, or creates an owned client.</summary>
    internal static (HttpClient Client, IDisposable? OwnedDisposable) FromOptional(HttpClient? httpClient)
    {
        if (httpClient is not null)
        {
            return (httpClient, null);
        }

        var created = new HttpClient();
        return (created, created);
    }

    /// <summary>Optional caller-supplied <see cref="HttpClient"/> with explicit ownership for <see cref="IDisposable.Dispose"/>.</summary>
    internal sealed class HttpClientLease : IDisposable
    {
        public HttpClient Client { get; }

        private readonly IDisposable? _ownedDisposable;

        public HttpClientLease(HttpClient? httpClient) =>
            (Client, _ownedDisposable) = FromOptional(httpClient);

        public void Dispose() => _ownedDisposable?.Dispose();
    }
}
