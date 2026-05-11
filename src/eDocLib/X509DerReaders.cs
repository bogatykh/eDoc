using Org.BouncyCastle.X509;

namespace eDocLib;

/// <summary>Shared <see cref="X509CertificateParser"/> / <see cref="X509CrlParser"/> for stateless DER reads.</summary>
internal static class X509DerReaders
{
    /// <summary>Stores the certificates.</summary>
    private static readonly X509CertificateParser Certificates = new();

    /// <summary>Stores the CRLs.</summary>
    private static readonly X509CrlParser Crls = new();

    /// <summary>Reads an X.509 certificate from DER bytes.</summary>
    internal static X509Certificate ReadCertificate(byte[] encoded) => Certificates.ReadCertificate(encoded);

    /// <summary>Reads an X.509 CRL from DER bytes.</summary>
    internal static X509Crl ReadCrl(byte[] encoded) => Crls.ReadCrl(encoded);
}
