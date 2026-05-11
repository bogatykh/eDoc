using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using eDocLib;
using eDocLib.Asic.Xades;

namespace eDocLib.Validation;

/// <summary>
/// Verifies detached XML-DSig + XAdES-BES style signatures produced by <see cref="XadesBesSigner"/> (RSA-SHA256 / RSA-SHA384, ECDSA).
/// </summary>
internal static partial class DetachedSignatureVerifier
{
    /// <summary>Verifies each <c>ds:Reference</c> digest against the in-memory payload map.</summary>
    public static bool TryVerifyReferenceDigests(
        XadesSignature signature,
        IReadOnlyDictionary<string, byte[]> payloadByRelativeUri,
        out string? error) =>
        TryVerifyReferenceDigests(
            signature,
            new InMemoryPayloadSource(payloadByRelativeUri ?? throw new ArgumentNullException(nameof(payloadByRelativeUri))),
            out error);

    /// <summary>Verifies each <c>ds:Reference</c> digest using the streaming payload source.</summary>
    /// <remarks>
    /// References without an XML transform chain hash the payload incrementally from the source stream, so the
    /// entire payload never has to be present in a single byte buffer. References with transforms still buffer
    /// (the System.Security.Cryptography.Xml transform API consumes an in-memory representation), but the
    /// buffering happens only for the affected reference rather than for every container payload.
    /// </remarks>
    internal static bool TryVerifyReferenceDigests(
        XadesSignature signature,
        IValidationPayloadSource payloadSource,
        out string? error)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(payloadSource);

        if (!TryGetSignatureXmlContext(signature, out var signedXml, out var doc, out _, out error))
        {
            return false;
        }

        return TryVerifyAllReferences(signedXml, doc, payloadSource, out error);
    }

    /// <summary>
    /// Verifies digest of every <c>ds:Reference</c> and the signature over canonical <c>ds:SignedInfo</c> (RSA or ECDSA).
    /// </summary>
    /// <param name="signature">Parsed XAdES signature document (typically the library’s internal ASiC signature implementation).</param>
    /// <param name="payloadByRelativeUri">Payload bytes keyed by reference URI (e.g. file path inside the ASiC container).</param>
    /// <param name="error">Human-readable failure reason.</param>
    /// <param name="trustPolicy">Optional; controls whether <c>xades:SigningCertificate</c> is mandatory (see <see cref="SignatureTrustPolicy.RequireXadesSigningCertificate"/>).</param>
    public static bool TryVerify(
        XadesSignature signature,
        IReadOnlyDictionary<string, byte[]> payloadByRelativeUri,
        out string? error,
        SignatureTrustPolicy? trustPolicy = null) =>
        TryVerify(
            signature,
            new InMemoryPayloadSource(payloadByRelativeUri ?? throw new ArgumentNullException(nameof(payloadByRelativeUri))),
            out error,
            trustPolicy);

    /// <inheritdoc cref="TryVerify(XadesSignature, IReadOnlyDictionary{string, byte[]}, out string?, SignatureTrustPolicy?)"/>
    internal static bool TryVerify(
        XadesSignature signature,
        IValidationPayloadSource payloadSource,
        out string? error,
        SignatureTrustPolicy? trustPolicy = null)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(payloadSource);

        if (!TryGetSignatureXmlContext(signature, out var signedXml, out var doc, out var sigEl, out error))
        {
            return false;
        }

        if (!TryVerifyAllReferences(signedXml, doc, payloadSource, out error))
        {
            return false;
        }

        if (signature.SigningCertificate is not X509Certificate2 cert)
        {
            error = "Signing certificate is missing from KeyInfo.";
            return false;
        }

        var allowNonSha256Ess = trustPolicy is not { RestrictSigningCertificateDigestToSha256: true };
        if (!SigningCertificateDigestVerifier.TryVerifyIfPresent(
                doc,
                cert,
                trustPolicy?.RequireXadesSigningCertificate ?? false,
                out error,
                sigEl,
                allowSha384CertDigest: allowNonSha256Ess,
                allowSha512CertDigest: allowNonSha256Ess))
        {
            return false;
        }

        var signedInfoBytes = XmlDsigCanonicalization.GetSignedInfoCanonicalBytes(doc);
        var sigBytes = GetSignatureBytesFromDom(doc);
        var method = signedXml.SignatureMethod ?? string.Empty;

        if (TryGetRsaHash(method, out var rsaHash))
        {
            return VerifyRsa(cert, signedInfoBytes, sigBytes, rsaHash, out error);
        }

        if (TryGetEcdsaHash(method, out var ecHash))
        {
            return VerifyEcdsa(cert, signedInfoBytes, sigBytes, ecHash, out error);
        }

        error = $"Unsupported SignatureMethod: {method}";
        return false;
    }

    /// <summary>Loads <see cref="SignedXml"/> / DOM for the signature and ensures <see cref="SignedXml.SignedInfo"/> exists.</summary>
    private static bool TryGetSignatureXmlContext(
        XadesSignature signature,
        out SignedXml signedXml,
        out XmlDocument doc,
        out XmlElement sigEl,
        out string? error)
    {
        signedXml = signature.SignedXmlCore;
        sigEl = signedXml.GetXml() ?? throw new CryptographicException("Signature element is missing.");
        if (sigEl.OwnerDocument == null)
        {
            doc = null!;
            error = "Signature element is missing.";
            return false;
        }

        doc = sigEl.OwnerDocument;
        if (signedXml.SignedInfo == null)
        {
            error = "SignedInfo is missing.";
            return false;
        }

        error = null;
        return true;
    }

    private static bool TryVerifyAllReferences(
        SignedXml signedXml,
        XmlDocument doc,
        IValidationPayloadSource payloadSource,
        out string? error)
    {
        foreach (Reference reference in signedXml.SignedInfo!.References.Cast<Reference>())
        {
            if (!TryVerifyReference(reference, doc, payloadSource, out error))
            {
                return false;
            }
        }

        error = null;
        return true;
    }

    /// <summary>Maps an RSA <c>ds:SignatureMethod</c> URI to its <see cref="HashAlgorithmName"/>.</summary>
    private static bool TryGetRsaHash(string method, out HashAlgorithmName hash)
    {
        switch (method)
        {
            case XadesSignatureAlgorithms.RsaWithSha256:
                hash = HashAlgorithmName.SHA256;
                return true;
            case XadesSignatureAlgorithms.RsaWithSha384:
                hash = HashAlgorithmName.SHA384;
                return true;
            default:
                hash = default;
                return false;
        }
    }

    /// <summary>Maps an ECDSA <c>ds:SignatureMethod</c> URI to its <see cref="HashAlgorithmName"/>.</summary>
    private static bool TryGetEcdsaHash(string method, out HashAlgorithmName hash)
    {
        switch (method)
        {
            case XadesSignatureAlgorithms.EcdsaWithSha256:
                hash = HashAlgorithmName.SHA256;
                return true;
            case XadesSignatureAlgorithms.EcdsaWithSha384:
                hash = HashAlgorithmName.SHA384;
                return true;
            case XadesSignatureAlgorithms.EcdsaWithSha512:
                hash = HashAlgorithmName.SHA512;
                return true;
            default:
                hash = default;
                return false;
        }
    }

    /// <summary>Verifies an RSA PKCS#1 v1.5 signature over <paramref name="signedInfoBytes"/>.</summary>
    private static bool VerifyRsa(
        X509Certificate2 cert,
        byte[] signedInfoBytes,
        byte[] sigBytes,
        HashAlgorithmName hash,
        out string? error)
    {
        using var rsa = cert.GetRSAPublicKey();
        if (rsa == null)
        {
            error = "Public key is not RSA.";
            return false;
        }

        if (!rsa.VerifyData(signedInfoBytes, sigBytes, hash, RSASignaturePadding.Pkcs1))
        {
            error = "RSA signature over SignedInfo is invalid.";
            return false;
        }

        error = null;
        return true;
    }

    /// <summary>Verifies an ECDSA signature (DER <c>SEQUENCE { r, s }</c>) over <paramref name="signedInfoBytes"/>.</summary>
    private static bool VerifyEcdsa(
        X509Certificate2 cert,
        byte[] signedInfoBytes,
        byte[] sigBytes,
        HashAlgorithmName hash,
        out string? error)
    {
        using var ec = cert.GetECDsaPublicKey();
        if (ec == null)
        {
            error = "Public key is not ECDSA.";
            return false;
        }

        if (!ec.VerifyData(signedInfoBytes, sigBytes, hash, DSASignatureFormat.Rfc3279DerSequence))
        {
            error = "ECDSA signature over SignedInfo is invalid.";
            return false;
        }

        error = null;
        return true;
    }

    /// <inheritdoc cref="TryVerify(XadesSignature, IReadOnlyDictionary{string, byte[]}, out string?, SignatureTrustPolicy?)"/>
    public static bool TryVerify(
        ISignature signature,
        IReadOnlyDictionary<string, byte[]> payloadByRelativeUri,
        out string? error,
        SignatureTrustPolicy? trustPolicy = null)
    {
        if (signature is not XadesSignature xs)
        {
            error = "Detached verification requires an XAdES-backed signature.";
            return false;
        }

        return TryVerify(xs, payloadByRelativeUri, out error, trustPolicy);
    }
}
