using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using eDocLib.Revocation;

namespace eDocLib.Revocation.Verify;

/// <summary>Partial class: per-artifact outcomes for embedded revocation verification.</summary>
internal static partial class EmbeddedRevocationVerifier
{
    /// <summary>
    /// Same rules as <see cref="TryVerifyUnsignedArtifacts"/>, but records one <see cref="RevocationArtifactOutcome"/>
    /// per non-empty OCSP or CRL blob.
    /// OCSP: each blob is checked individually; the aggregate requirement remains that at least one proves <c>good</c> status.
    /// CRL: each blob must pass (signature + signer not revoked).
    /// </summary>
    public static bool TryVerifyUnsignedArtifactsDetailed(
        X509Certificate2 signingCertificate,
        IReadOnlyList<byte[]> ocspDerBlobs,
        IReadOnlyList<byte[]> crlDerBlobs,
        IReadOnlyList<X509Certificate2> chainFromLeaf,
        out string? error,
        out IReadOnlyList<RevocationArtifactOutcome> outcomes,
        EmbeddedRevocationVerificationOptions? verificationOptions = null,
        X509Certificate2Collection? additionalCrlIssuerCertificates = null)
    {
        ArgumentNullException.ThrowIfNull(signingCertificate);
        ArgumentNullException.ThrowIfNull(ocspDerBlobs);
        ArgumentNullException.ThrowIfNull(crlDerBlobs);
        ArgumentNullException.ThrowIfNull(chainFromLeaf);

        error = null;
        var list = new List<RevocationArtifactOutcome>();

        if (ocspDerBlobs.Count > 0)
        {
            var ordinal = 0;
            var anyNonEmpty = false;
            var anyGood = false;
            string? lastErr = null;
            foreach (var der in ocspDerBlobs)
            {
                if (der is not { Length: > 0 })
                {
                    continue;
                }

                anyNonEmpty = true;
                var ok = TryVerifyOneOcsp(
                    der,
                    signingCertificate,
                    chainFromLeaf,
                    verificationOptions,
                    out var oneErr);
                list.Add(new RevocationArtifactOutcome(RevocationArtifactKind.Ocsp, ordinal, ok, ok ? null : oneErr));
                if (ok)
                {
                    anyGood = true;
                }
                else
                {
                    lastErr = oneErr;
                }

                ordinal++;
            }

            if (!anyNonEmpty)
            {
                error = "Embedded OCSP list contains no non-empty DER blobs.";
                outcomes = list;
                return false;
            }

            if (!anyGood)
            {
                error = lastErr ?? "No embedded OCSP response verified for the signing certificate.";
                outcomes = list;
                return false;
            }
        }

        var crlOrdinal = 0;
        foreach (var crlDer in crlDerBlobs)
        {
            if (crlDer is not { Length: > 0 })
            {
                continue;
            }

            var ok = TryVerifyOneCrlBlob(
                crlDer,
                signingCertificate,
                chainFromLeaf,
                additionalCrlIssuerCertificates,
                out var crlErr);
            list.Add(new RevocationArtifactOutcome(RevocationArtifactKind.Crl, crlOrdinal, ok, ok ? null : crlErr));
            if (!ok)
            {
                error = crlErr;
                outcomes = list;
                return false;
            }

            crlOrdinal++;
        }

        outcomes = list;
        return true;
    }
}
