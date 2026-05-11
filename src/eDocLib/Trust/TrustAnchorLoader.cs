using System.Security.Cryptography.X509Certificates;

namespace eDocLib.Trust;

/// <summary>Loads trust anchors for <see cref="Validation.SignatureTrustPolicy.CustomTrustAnchors"/> from PEM text or PKCS#12 (<c>.pfx</c>/<c>.p12</c>).</summary>
public static class TrustAnchorLoader
{
    /// <summary>Imports all PEM-encoded certificates (one or more <c>BEGIN CERTIFICATE</c> blocks).</summary>
    public static X509Certificate2Collection FromPem(ReadOnlySpan<char> pem)
    {
        var coll = new X509Certificate2Collection();
        coll.ImportFromPem(pem);
        return coll;
    }

    /// <summary>Loads PEM-encoded certificates from a file (one or more <c>BEGIN CERTIFICATE</c> blocks).</summary>
    public static X509Certificate2Collection FromPemFile(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        var text = File.ReadAllText(path);
        return FromPem(text);
    }

    /// <summary>
    /// Imports a PKCS#12 store (typically only public certificates used as anchors; private keys are ignored for trust).
    /// </summary>
    /// <remarks>
    /// Defaults to <see cref="X509KeyStorageFlags.DefaultKeySet"/> for cross-platform portability:
    /// macOS rejects <see cref="X509KeyStorageFlags.EphemeralKeySet"/> with <see cref="PlatformNotSupportedException"/>.
    /// Trust anchors do not need a private key, so the chosen flag affects only any incidental key material in the PFX
    /// and the caller can override when running on Linux or Windows.
    /// </remarks>
    public static X509Certificate2Collection FromPfx(string path, string? password, X509KeyStorageFlags flags = X509KeyStorageFlags.DefaultKeySet)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        var coll = new X509Certificate2Collection();
        coll.Import(path, password, flags);
        return coll;
    }

}
