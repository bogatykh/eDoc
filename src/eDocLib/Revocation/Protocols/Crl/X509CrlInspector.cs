using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.X509;

namespace eDocLib.Revocation.Protocols.Crl;

/// <summary>CRL parsing, issuer signature check, and <see cref="X509Crl.IsRevoked"/> helper.</summary>
internal static class X509CrlInspector
{
    /// <summary>Attempts to parse.</summary>
    public static bool TryParse(byte[] crlDer, out X509Crl? crl, out string? error)
    {
        ArgumentNullException.ThrowIfNull(crlDer);
        crl = null;
        error = null;
        try
        {
            crl = X509DerReaders.ReadCrl(crlDer);
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    /// <summary><see cref="M:Org.BouncyCastle.X509.X509Crl.Verify(Org.BouncyCastle.Crypto.IVerifierFactoryProvider)"/> using the CRL issuer’s public key.</summary>
    public static bool TryVerifyIssuerSignature(X509Crl crl, X509Certificate2 issuer, out string? error)
    {
        ArgumentNullException.ThrowIfNull(crl);
        ArgumentNullException.ThrowIfNull(issuer);
        error = null;
        try
        {
            var issuerCert = X509DerReaders.ReadCertificate(issuer.RawData);
            var provider = new Asn1VerifierFactoryProvider(issuerCert.GetPublicKey());
            crl.Verify(provider);
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    /// <summary>Whether <paramref name="certificate"/> appears on this CRL (issuer must match CRL issuer in real PKIX checks).</summary>
    public static bool IsCertificateRevoked(X509Crl crl, X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(crl);
        ArgumentNullException.ThrowIfNull(certificate);
        var cert = X509DerReaders.ReadCertificate(certificate.RawData);
        return crl.IsRevoked(cert);
    }
}
