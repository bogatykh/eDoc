namespace eDocLib.Revocation.Online;

/// <summary>Defaults for HTTP OCSP/CRL fetch size and time bounds.</summary>
internal static class RevocationFetchLimits
{
    /// <summary>Default cap on each OCSP or CRL HTTP response body (bytes).</summary>
    public const int DefaultMaxResponseBytes = 2 * 1024 * 1024;

    /// <summary>Default time bound for a full fetch attempt (OCSP + CRL tries).</summary>
    public static readonly TimeSpan DefaultFetchTimeout = TimeSpan.FromSeconds(30);
}
