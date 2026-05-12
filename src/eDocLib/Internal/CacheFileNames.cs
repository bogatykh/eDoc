using System.Security.Cryptography;
using System.Text;

namespace eDocLib.Internal;

/// <summary>Helpers for deterministic, filesystem-safe cache file names.</summary>
internal static class CacheFileNames
{
    /// <summary>Returns uppercase SHA-256 hex of the UTF-8 encoded <paramref name="key"/>.</summary>
    public static string Sha256HexKey(string key) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key)));
}
