using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using eDocLib.Revocation;
using eDocLib.Revocation.Protocols.Crl;

namespace eDocLib.Revocation.Verify;

/// <summary>
/// Validates unsigned XAdES <c>RevocationValues</c> (embedded OCSP and CRL DER) against the signing certificate
/// and an established PKIX path (end-entity first, toward the trust anchor).
/// </summary>
internal static partial class EmbeddedRevocationVerifier
{
    /// <summary>
    /// Verifies embedded OCSP and CRL blobs. Empty lists are ignored (success).
    /// OCSP: at least one response must verify cryptographically and contain a <c>good</c> status for the signing certificate
    /// (matched via full RFC 6960 <c>CertID</c> against an issuer in the chain, not serial number alone).
    /// CRL: each CRL must verify with some certificate from <paramref name="chainFromLeaf"/> or from
    /// <paramref name="additionalCrlIssuerCertificates"/> (when validating embedded CRL, matches <c>SignatureTrustPolicy.ExtraChainCertificates</c>)
    /// when the delegated CRL issuer is not part of the built signer path; must not list the signing certificate as revoked.
    /// </summary>
    public static bool TryVerifyUnsignedArtifacts(
        X509Certificate2 signingCertificate,
        IReadOnlyList<byte[]> ocspDerBlobs,
        IReadOnlyList<byte[]> crlDerBlobs,
        IReadOnlyList<X509Certificate2> chainFromLeaf,
        out string? error,
        EmbeddedRevocationVerificationOptions? verificationOptions = null,
        X509Certificate2Collection? additionalCrlIssuerCertificates = null) =>
        TryVerifyUnsignedArtifactsDetailed(
            signingCertificate,
            ocspDerBlobs,
            crlDerBlobs,
            chainFromLeaf,
            out error,
            out _,
            verificationOptions,
            additionalCrlIssuerCertificates);

    private static bool TryVerifyOneCrlBlob(
        byte[] crlDer,
        X509Certificate2 signingCertificate,
        IReadOnlyList<X509Certificate2> chainFromLeaf,
        X509Certificate2Collection? additionalCrlIssuerCertificates,
        out string? error)
    {
        if (!X509CrlInspector.TryParse(crlDer, out var crl, out var parseErr) || crl is null)
        {
            error = parseErr ?? "Invalid embedded CRL.";
            return false;
        }

        if (!TryFindCrlIssuerAndVerify(crl, chainFromLeaf, additionalCrlIssuerCertificates, out var crlErr))
        {
            error = crlErr;
            return false;
        }

        if (X509CrlInspector.IsCertificateRevoked(crl, signingCertificate))
        {
            error = "Signing certificate is revoked according to an embedded CRL.";
            return false;
        }

        error = null;
        return true;
    }

    private static bool TryFindCrlIssuerAndVerify(
        Org.BouncyCastle.X509.X509Crl crl,
        IReadOnlyList<X509Certificate2> chainFromLeaf,
        X509Certificate2Collection? additionalCrlIssuerCertificates,
        out string? error)
    {
        var tried = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var c in chainFromLeaf)
        {
            tried.Add(c.Thumbprint);
            if (X509CrlInspector.TryVerifyIssuerSignature(crl, c, out _))
            {
                error = null;
                return true;
            }
        }

        if (additionalCrlIssuerCertificates is not null)
        {
            foreach (X509Certificate2 c in additionalCrlIssuerCertificates)
            {
                if (!tried.Add(c.Thumbprint))
                {
                    continue;
                }

                if (X509CrlInspector.TryVerifyIssuerSignature(crl, c, out _))
                {
                    error = null;
                    return true;
                }
            }
        }

        error = additionalCrlIssuerCertificates is { Count: > 0 }
            ? "Embedded CRL signature could not be verified with any certificate in the established PKIX path or in ExtraChainCertificates."
            : "Embedded CRL signature could not be verified with any certificate in the established PKIX path.";
        return false;
    }
}
