using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace eDocLib.Revocation.Protocols.Ocsp;

/// <summary>Helpers for recognizing RFC 6960 OCSP responder certificates via extended key usage.</summary>
internal static class OcspResponderPolicy
{
    /// <summary>id-kp-OCSPSigning</summary>
    internal const string OcspSigningExtendedKeyUsageOid = "1.3.6.1.5.5.7.3.9";

    /// <summary>Returns whether the certificate allows OCSP signing.</summary>
    internal static bool CertificateHasOcspSigningExtendedKeyUsage(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        foreach (var ext in certificate.Extensions)
        {
            if (ext.Oid?.Value != "2.5.29.37")
            {
                continue;
            }

            var decoded = new X509EnhancedKeyUsageExtension(ext, ext.Critical);
            foreach (Oid oid in decoded.EnhancedKeyUsages)
            {
                if (oid.Value == OcspSigningExtendedKeyUsageOid)
                {
                    return true;
                }
            }
        }

        return false;
    }
}
