using System.Net.Http;

namespace eDocLib.Revocation.Online;

/// <summary>Shared optional ownership when callers omit a shared <see cref="HttpClient"/>.</summary>
internal static class HttpClientOwnership
{
    /// <summary>Stores the HTTP client.</summary>
    internal static (HttpClient Client, IDisposable? OwnedDisposable) FromOptional(HttpClient? httpClient)
    {
        if (httpClient is not null)
        {
            return (httpClient, null);
        }

        var created = new HttpClient();
        return (created, created);
    }
}
