using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace eDocLib.Asic.Xades;

/// <summary>
/// PKCS#7 (certificate-only) export/import for <see cref="CertificateValuesWireFormat.Pkcs7"/>.
/// </summary>
internal static class X509Pkcs7CertificateBag
{
    /// <summary>Exports the certificates as a PKCS#7 SignedData blob suitable for <c>xades:EncapsulatedPKIData</c>.</summary>
    public static byte[] ExportPkcs7(IEnumerable<X509Certificate2> certificates)
    {
        ArgumentNullException.ThrowIfNull(certificates);
        var coll = new X509Certificate2Collection();
        foreach (var c in certificates)
        {
            ArgumentNullException.ThrowIfNull(c);
            coll.Add(c);
        }

        if (coll.Count == 0)
        {
            throw new ArgumentException("At least one certificate is required.", nameof(certificates));
        }

        var exported = coll.Export(X509ContentType.Pkcs7);
        if (exported is null || exported.Length == 0)
        {
            throw new CryptographicException("PKCS#7 export returned no data.");
        }

        return exported;
    }

    /// <summary>Imports certificates from a PKCS#7 blob (certificate store / degenerate CMS).</summary>
    public static bool TryImportCertificates(ReadOnlySpan<byte> pkcs7Der, [NotNullWhen(true)] out X509Certificate2Collection? certificates)
    {
        certificates = null;
        if (pkcs7Der.IsEmpty)
        {
            return false;
        }

        try
        {
            var coll = new X509Certificate2Collection();
            coll.Import(pkcs7Der.ToArray());
            if (coll.Count == 0)
            {
                return false;
            }

            certificates = coll;
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }
}
