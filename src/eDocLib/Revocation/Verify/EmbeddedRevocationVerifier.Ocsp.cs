using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Utilities;
using eDocLib.Revocation.Protocols.Der;
using eDocLib.Revocation.Protocols.Ocsp;

namespace eDocLib.Revocation.Verify;

/// <summary>Partial class: OCSP blob verification logic shared by embedded revocation checks.</summary>
internal static partial class EmbeddedRevocationVerifier
{
    /// <summary>Returns whether the OCSP list verifies the signer.</summary>
    private static bool OcspListVerified(
        IReadOnlyList<byte[]> ocspDerBlobs,
        X509Certificate2 signingCertificate,
        IReadOnlyList<X509Certificate2> chainFromLeaf,
        EmbeddedRevocationVerificationOptions? verificationOptions,
        out string? error)
    {
        error = null;
        string? lastErr = null;
        var anyDer = false;
        foreach (var der in ocspDerBlobs)
        {
            if (der is not { Length: > 0 })
            {
                continue;
            }

            anyDer = true;
            if (TryVerifyOneOcsp(der, signingCertificate, chainFromLeaf, verificationOptions, out lastErr))
            {
                return true;
            }
        }

        if (!anyDer)
        {
            error = "Embedded OCSP list contains no non-empty DER blobs.";
            return false;
        }

        error = lastErr ?? "No embedded OCSP response verified for the signing certificate.";
        return false;
    }

    /// <summary>Attempts to verify one OCSP.</summary>
    internal static bool TryVerifyOneOcsp(
        byte[] der,
        X509Certificate2 signingCertificate,
        IReadOnlyList<X509Certificate2> chainFromLeaf,
        EmbeddedRevocationVerificationOptions? verificationOptions,
        out string? error)
    {
        if (!TryVerifyOcspCryptographicSignature(der, chainFromLeaf, verificationOptions, out error))
        {
            return false;
        }

        var vo = verificationOptions;
        var needEmbedded = vo is { RequireEmbeddedResponderOcspSigningExtendedKeyUsage: true }
                           or { ValidateEmbeddedOcspResponderCertificateChain: true };
        if (needEmbedded)
        {
            if (!OcspResponseSignatureVerifier.TryGetFirstEmbeddedCertificate(der, out var embedded, out var embErr)
                || embedded is null)
            {
                error = embErr
                        ?? "OCSP policy requires an embedded responder certificate in the OCSP response.";
                return false;
            }

            using (embedded)
            {
                if (vo!.RequireEmbeddedResponderOcspSigningExtendedKeyUsage
                    && !OcspResponderPolicy.CertificateHasOcspSigningExtendedKeyUsage(embedded))
                {
                    error =
                        "Embedded OCSP responder certificate does not include the id-kp-OCSPSigning extended key usage.";
                    return false;
                }

                if (vo.ValidateEmbeddedOcspResponderCertificateChain
                    && !TryValidateResponderPkixChain(embedded, vo, out error))
                {
                    return false;
                }
            }
        }

        return OcspShowsSignerGood(der, signingCertificate, chainFromLeaf, out error);
    }

    /// <summary>Attempts to validate responder PKIX chain.</summary>
    private static bool TryValidateResponderPkixChain(
        X509Certificate2 responder,
        EmbeddedRevocationVerificationOptions options,
        out string? error)
    {
        error = null;
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

        if (options.ResponderChainExtraStore is { Count: > 0 })
        {
            foreach (var c in options.ResponderChainExtraStore)
            {
                chain.ChainPolicy.ExtraStore.Add(c);
            }
        }

        if (options.ResponderChainTrustAnchors is { Count: > 0 })
        {
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            foreach (var a in options.ResponderChainTrustAnchors)
            {
                chain.ChainPolicy.CustomTrustStore.Add(a);
            }
        }

        if (!chain.Build(responder))
        {
            var st = chain.ChainStatus.Length > 0
                ? string.Join("; ", chain.ChainStatus.Select(s => s.StatusInformation.Trim()))
                : "Unknown chain error.";
            error = "OCSP responder PKIX validation failed: " + st;
            return false;
        }

        return true;
    }

    /// <summary>Attempts to verify OCSP cryptographic signature.</summary>
    private static bool TryVerifyOcspCryptographicSignature(
        byte[] der,
        IReadOnlyList<X509Certificate2> chainFromLeaf,
        EmbeddedRevocationVerificationOptions? verificationOptions,
        out string? error)
    {
        var embeddedOnly = verificationOptions?.RequireOcspSignatureByEmbeddedResponderOnly == true;
        if (OcspResponseSignatureVerifier.TryVerifyBasicSignatureUsingEmbeddedResponderCert(der, out _))
        {
            error = null;
            return true;
        }

        if (embeddedOnly)
        {
            error =
                "Strict embedded OCSP policy requires a signature verifiable with a certificate embedded in the OCSP response.";
            return false;
        }

        foreach (var cert in chainFromLeaf)
        {
            if (OcspResponseSignatureVerifier.TryVerifyBasicSignature(der, cert, out _))
            {
                error = null;
                return true;
            }
        }

        error =
            "OCSP response signature could not be verified with the embedded responder certificate or any certificate in the established chain.";
        return false;
    }

    /// <summary>Returns whether OCSP reports the signer as good.</summary>
    private static bool OcspShowsSignerGood(
        byte[] der,
        X509Certificate2 signingCertificate,
        IReadOnlyList<X509Certificate2> chainFromLeaf,
        out string? error)
    {
        if (!OcspResponseInternals.TryGetSuccessfulBasic(der, out var basic, out var parseErr) || basic is null)
        {
            error = parseErr ?? "Could not read OCSP Basic response.";
            return false;
        }

        var leafBc = X509DerReaders.ReadCertificate(signingCertificate.RawData);
        foreach (SingleResp single in basic.Responses)
        {
            if (!CertIdMatchesLeafAndIssuerFromChain(single.GetCertID(), leafBc, chainFromLeaf))
            {
                continue;
            }

            var certStatus = single.GetCertStatus();
            if (certStatus == null)
            {
                error = null;
                return true;
            }

            if (certStatus is RevokedStatus)
            {
                error = "Signing certificate is revoked according to embedded OCSP.";
                return false;
            }

            error = "OCSP certificate status for the signing certificate is not good.";
            return false;
        }

        error = "Embedded OCSP response does not include the signing certificate (no matching CertID).";
        return false;
    }

    /// <summary>
    /// Requires the same hash algorithm, issuer name/key hashes, and serial as in the OCSP <c>CertID</c>,
    /// with the issuer taken from the PKIX path (any CA in the chain except the leaf).
    /// </summary>
    private static bool CertIdMatchesLeafAndIssuerFromChain(
        CertificateID cid,
        Org.BouncyCastle.X509.X509Certificate leafBc,
        IReadOnlyList<X509Certificate2> chainFromLeaf)
    {
        if (!cid.SerialNumber.Equals(leafBc.SerialNumber))
        {
            return false;
        }

        var hashOid = cid.HashAlgOid;
        foreach (var issuerDotNet in chainFromLeaf.Skip(1))
        {
            var issuerBc = X509DerReaders.ReadCertificate(issuerDotNet.RawData);
            try
            {
#pragma warning disable CS0618 // BC 2.4: replacement CertificateID factory not yet adopted; must match OCSP CertID hash algorithm.
                var expected = new CertificateID(hashOid, issuerBc, leafBc.SerialNumber);
#pragma warning restore CS0618
                if (Arrays.AreEqual(cid.GetIssuerNameHash(), expected.GetIssuerNameHash())
                    && Arrays.AreEqual(cid.GetIssuerKeyHash(), expected.GetIssuerKeyHash()))
                {
                    return true;
                }
            }
            catch (OcspException)
            {
                // Issuer cannot be used for this hash algorithm / cert shape; try next.
            }
        }

        return false;
    }
}
