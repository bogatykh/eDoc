using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;
using DerX509Certificate = Org.BouncyCastle.X509.X509Certificate;
using eDocLib.Revocation.Protocols.Der;

namespace eDocLib.Revocation.Protocols.Ocsp;

/// <summary>Delegates to <see cref="BasicOcspResp.Verify"/>; parsing uses <see cref="OcspResponseInternals"/>.</summary>
internal static class OcspResponseSignatureVerifier
{
    /// <summary>Attempts to verify basic signature.</summary>
    public static bool TryVerifyBasicSignature(
        byte[] ocspResponseDer,
        X509Certificate2 responderCertificate,
        out string? error)
    {
        ArgumentNullException.ThrowIfNull(ocspResponseDer);
        ArgumentNullException.ThrowIfNull(responderCertificate);

        if (!OcspResponseInternals.TryGetSuccessfulBasic(ocspResponseDer, out var basic, out error))
        {
            return false;
        }

        try
        {
            var responder = X509DerReaders.ReadCertificate(responderCertificate.RawData);
            basic!.Verify(responder.GetPublicKey());
            error = null;
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    /// <summary>Uses the first certificate embedded in the Basic OCSP response (if any).</summary>
    public static bool TryVerifyBasicSignatureUsingEmbeddedResponderCert(byte[] ocspResponseDer, out string? error)
    {
        ArgumentNullException.ThrowIfNull(ocspResponseDer);

        if (!OcspResponseInternals.TryGetSuccessfulBasic(ocspResponseDer, out var basic, out error))
        {
            return false;
        }

        if (basic!.GetCertificates() is not { } certs)
        {
            error = "OCSP Basic response contains no embedded certificates.";
            return false;
        }

        AsymmetricKeyParameter? pub = null;
        foreach (DerX509Certificate x509 in certs.EnumerateMatches(new X509CertStoreSelector()))
        {
            pub = x509.GetPublicKey();
            break;
        }

        if (pub == null)
        {
            error = "Could not extract a responder public key from embedded OCSP certificates.";
            return false;
        }

        try
        {
            basic.Verify(pub);
            error = null;
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    /// <summary>First certificate in the Basic OCSP response’s <c>certs</c> sequence, if any.</summary>
    public static bool TryGetFirstEmbeddedCertificate(
        byte[] ocspResponseDer,
        [NotNullWhen(true)] out X509Certificate2? certificate,
        out string? error)
    {
        certificate = null;
        ArgumentNullException.ThrowIfNull(ocspResponseDer);

        if (!OcspResponseInternals.TryGetSuccessfulBasic(ocspResponseDer, out var basic, out error))
        {
            return false;
        }

        if (basic!.GetCertificates() is not { } certs)
        {
            error = "OCSP Basic response contains no embedded certificates.";
            return false;
        }

        foreach (DerX509Certificate x509 in certs.EnumerateMatches(new X509CertStoreSelector()))
        {
            certificate = new X509Certificate2(x509.GetEncoded());
            error = null;
            return true;
        }

        error = "Could not extract a certificate from the OCSP response’s embedded certificate set.";
        return false;
    }
}
