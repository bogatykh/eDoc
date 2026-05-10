using System.Security.Cryptography.X509Certificates;

namespace eDocLib.Revocation.Cache;

/// <summary>Stable cache key strings for OCSP/CRL DER (versioned prefix for future algorithm changes).</summary>
internal static class RevocationDerCacheKeys
{
    /// <summary>Defines the version value.</summary>
    private const string Version = "v1";

    /// <summary>Key for OCSP response: responder URI + leaf/issuer thumbprints + leaf serial (hex).</summary>
    public static string Ocsp(X509Certificate2 endEntity, X509Certificate2 issuer, Uri ocspResponder)
    {
        ArgumentNullException.ThrowIfNull(endEntity);
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(ocspResponder);
        var serial = Convert.ToHexString(endEntity.GetSerialNumber());
        return $"ocsp|{Version}|{ocspResponder.AbsoluteUri}|{endEntity.Thumbprint}|{issuer.Thumbprint}|{serial}";
    }

    /// <summary>Key for CRL GET response.</summary>
    public static string Crl(Uri crlUri)
    {
        ArgumentNullException.ThrowIfNull(crlUri);
        return $"crl|{Version}|{crlUri.AbsoluteUri}";
    }
}
