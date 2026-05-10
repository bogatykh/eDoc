using System.Security.Cryptography.X509Certificates;

namespace eDocLib.Asic.Xades;

/// <summary>Partial class: orchestrates certificate + revocation embedding for LT-style profiles.</summary>
internal static partial class XadesBesSigner
{
    /// <summary>
    /// Appends unsigned XAdES-LT-style material: optional <see cref="AppendUnsignedCertificateValues"/> and/or
    /// <see cref="AppendUnsignedRevocationValues"/> when the corresponding inputs are non-empty.
    /// </summary>
    /// <exception cref="ArgumentException">Both certificate and revocation inputs are empty.</exception>
    public static void AppendUnsignedLongTermMaterial(
        XadesSignature signature,
        IEnumerable<X509Certificate2>? certificatesToEmbed = null,
        IEnumerable<byte[]>? ocspResponseDer = null,
        IEnumerable<byte[]>? crlDer = null,
        CertificateValuesWireFormat certificateValuesFormat = CertificateValuesWireFormat.EncapsulatedX509)
    {
        ArgumentNullException.ThrowIfNull(signature);

        var certList = certificatesToEmbed?.Where(c => c != null).ToList() ?? [];
        var ocsp = ocspResponseDer?.Where(b => b is { Length: > 0 }).ToList() ?? [];
        var crl = crlDer?.Where(b => b is { Length: > 0 }).ToList() ?? [];

        if (certList.Count == 0 && ocsp.Count == 0 && crl.Count == 0)
        {
            throw new ArgumentException(
                "Provide at least one certificate to embed or one OCSP/CRL DER blob.",
                nameof(certificatesToEmbed));
        }

        if (certList.Count > 0)
        {
            if (certificateValuesFormat == CertificateValuesWireFormat.Pkcs7)
            {
                AppendUnsignedCertificateValuesPkcs7(signature, certList);
            }
            else
            {
                AppendUnsignedCertificateValues(signature, certList);
            }
        }

        if (ocsp.Count > 0 || crl.Count > 0)
        {
            AppendUnsignedRevocationValues(signature, ocsp, crl);
        }
    }
}
