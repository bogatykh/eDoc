using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace eDocLib.Revocation.Online;

/// <summary>
/// Host-level checks for revocation URLs. Hostnames are not resolved; only literal IP addresses in the URI host are classified.
/// </summary>
internal static class RevocationFetchUriPolicy
{
    /// <summary>
    /// Requires <c>http</c> or <c>https</c>. When <paramref name="rejectLiteralPrivateAndLoopbackHosts"/> is <c>true</c>,
    /// literal loopback, RFC 1918, IPv4 link-local, IPv6 ULA/link-local/loopback hosts are rejected (SSRF hardening for CDP/AIA).
    /// </summary>
    public static bool IsAllowed(Uri uri, bool rejectLiteralPrivateAndLoopbackHosts, out string? error)
    {
        ArgumentNullException.ThrowIfNull(uri);
        error = null;

        if (uri.Scheme is not ("http" or "https"))
        {
            error = $"Revocation URI scheme '{uri.Scheme}' is not allowed (only http and https).";
            return false;
        }

        if (!rejectLiteralPrivateAndLoopbackHosts)
        {
            return true;
        }

        var host = uri.Host;
        if (!IPAddress.TryParse(host, out var ip))
        {
            return true;
        }

        if (IsRestrictedLiteralAddress(ip))
        {
            error = $"Revocation URI host '{host}' is not permitted when private/loopback literal rejection is enabled.";
            return false;
        }

        return true;
    }

    /// <summary>Attempts to validate certificate revocation URIs.</summary>
    public static bool TryValidateCertificateRevocationUris(
        X509Certificate2 endEntity,
        bool rejectLiteralPrivateAndLoopbackHosts,
        out string? error)
    {
        ArgumentNullException.ThrowIfNull(endEntity);
        error = null;
        if (!rejectLiteralPrivateAndLoopbackHosts)
        {
            return true;
        }

        if (X509RevocationUriDiscovery.TryGetOcspHttpUri(endEntity, out var ocsp) && ocsp is not null)
        {
            if (!IsAllowed(ocsp, true, out error))
            {
                return false;
            }
        }

        foreach (var crl in X509RevocationUriDiscovery.GetCrlHttpUris(endEntity))
        {
            if (!IsAllowed(crl, true, out error))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Returns whether restricted literal address.</summary>
    private static bool IsRestrictedLiteralAddress(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip))
        {
            return true;
        }

        switch (ip.AddressFamily)
        {
            case AddressFamily.InterNetwork:
            {
                var b = ip.GetAddressBytes();
                if (b.Length != 4)
                {
                    return false;
                }

                if (b[0] == 10)
                {
                    return true;
                }

                if (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                {
                    return true;
                }

                if (b[0] == 192 && b[1] == 168)
                {
                    return true;
                }

                // IPv4 link-local
                if (b[0] == 169 && b[1] == 254)
                {
                    return true;
                }

                return false;
            }
            case AddressFamily.InterNetworkV6:
            {
                if (ip.IsIPv6LinkLocal)
                {
                    return true;
                }

                var b = ip.GetAddressBytes();
                if (b.Length != 16)
                {
                    return false;
                }

                // Unique local IPv6 (fc00::/7)
                if (b[0] == 0xfc || b[0] == 0xfd)
                {
                    return true;
                }

                return false;
            }
            default:
                return false;
        }
    }
}
