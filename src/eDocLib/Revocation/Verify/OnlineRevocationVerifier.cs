using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using eDocLib.Revocation;
using eDocLib.Revocation.Online;

namespace eDocLib.Revocation.Verify;

/// <summary>
/// Validates revocation material obtained over HTTP (same rules as unsigned XAdES <c>RevocationValues</c> via
/// <see cref="EmbeddedRevocationVerifier"/>), but requires at least one non-empty OCSP or CRL payload.
/// </summary>
internal static class OnlineRevocationVerifier
{
    /// <summary>
    /// Fails when both OCSP and CRL lists are empty or contain only empty byte arrays; otherwise delegates to
    /// <see cref="EmbeddedRevocationVerifier.TryVerifyUnsignedArtifacts"/>.
    /// </summary>
    public static bool TryVerifyFetched(
        X509Certificate2 signingCertificate,
        RevocationMaterialFetchResult fetched,
        IReadOnlyList<X509Certificate2> chainFromLeaf,
        out string? error,
        EmbeddedRevocationVerificationOptions? verificationOptions = null,
        X509Certificate2Collection? additionalCrlIssuerCertificates = null)
    {
        ArgumentNullException.ThrowIfNull(signingCertificate);
        ArgumentNullException.ThrowIfNull(chainFromLeaf);

        error = null;
        if (!HasNonEmptyBlob(fetched.OcspResponses) && !HasNonEmptyBlob(fetched.Crls))
        {
            error =
                "Online revocation: no OCSP or CRL bytes were retrieved (missing AIA/CDP on the certificate, unreachable responders, or HTTP errors).";
            return false;
        }

        return EmbeddedRevocationVerifier.TryVerifyUnsignedArtifacts(
            signingCertificate,
            fetched.OcspResponses,
            fetched.Crls,
            chainFromLeaf,
            out error,
            verificationOptions,
            additionalCrlIssuerCertificates);
    }

    /// <summary>
    /// Same as <see cref="TryVerifyFetched"/>, with per-blob <see cref="RevocationArtifactOutcome"/> entries
    /// (after the empty-material guard succeeds).
    /// </summary>
    public static bool TryVerifyFetchedDetailed(
        X509Certificate2 signingCertificate,
        RevocationMaterialFetchResult fetched,
        IReadOnlyList<X509Certificate2> chainFromLeaf,
        out string? error,
        out IReadOnlyList<RevocationArtifactOutcome> outcomes,
        EmbeddedRevocationVerificationOptions? verificationOptions = null,
        X509Certificate2Collection? additionalCrlIssuerCertificates = null)
    {
        ArgumentNullException.ThrowIfNull(signingCertificate);
        ArgumentNullException.ThrowIfNull(fetched);
        ArgumentNullException.ThrowIfNull(chainFromLeaf);

        outcomes = Array.Empty<RevocationArtifactOutcome>();
        error = null;
        if (!HasNonEmptyBlob(fetched.OcspResponses) && !HasNonEmptyBlob(fetched.Crls))
        {
            error =
                "Online revocation: no OCSP or CRL bytes were retrieved (missing AIA/CDP on the certificate, unreachable responders, or HTTP errors).";
            return false;
        }

        return EmbeddedRevocationVerifier.TryVerifyUnsignedArtifactsDetailed(
            signingCertificate,
            fetched.OcspResponses,
            fetched.Crls,
            chainFromLeaf,
            out error,
            out outcomes,
            verificationOptions,
            additionalCrlIssuerCertificates);
    }

    /// <summary>Returns whether non empty blob.</summary>
    private static bool HasNonEmptyBlob(IReadOnlyList<byte[]> blobs)
    {
        foreach (var b in blobs)
        {
            if (b is { Length: > 0 })
            {
                return true;
            }
        }

        return false;
    }
}
