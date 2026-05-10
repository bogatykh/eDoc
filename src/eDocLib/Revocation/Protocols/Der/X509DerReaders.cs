using Org.BouncyCastle.X509;

namespace eDocLib.Revocation.Protocols.Der;

/// <summary>Shared <see cref="X509CertificateParser"/> / <see cref="X509CrlParser"/> for stateless DER reads.</summary>
internal static class X509DerReaders
{
    /// <summary>Stores the certificates.</summary>
    private static readonly X509CertificateParser Certificates = new();
    /// <summary>Stores the crls.</summary>
    private static readonly X509CrlParser Crls = new();

    /// <summary>Reads certificate.</summary>
    internal static X509Certificate ReadCertificate(byte[] encoded) => Certificates.ReadCertificate(encoded);

    /// <summary>Reads CRL.</summary>
    internal static X509Crl ReadCrl(byte[] encoded) => Crls.ReadCrl(encoded);
}
