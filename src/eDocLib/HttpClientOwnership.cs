namespace eDocLib;

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
}
