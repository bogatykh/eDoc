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
internal static class DetachedSignatureVerifier
{
    /// <summary>Attempts to verify reference digests.</summary>
    public static bool TryVerifyReferenceDigests(
        XadesSignature signature,
        IReadOnlyDictionary<string, byte[]> payloadByRelativeUri,
        out string? error)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(payloadByRelativeUri);

        error = null;
        var signedXml = signature.SignedXmlCore;
        var sigEl = signedXml.GetXml() ?? throw new CryptographicException("Signature element is missing.");
        if (sigEl.OwnerDocument == null)
        {
            error = "Signature element is missing.";
            return false;
        }

        var doc = sigEl.OwnerDocument;

        if (signedXml.SignedInfo == null)
        {
            error = "SignedInfo is missing.";
            return false;
        }

        foreach (Reference reference in signedXml.SignedInfo.References.Cast<Reference>())
        {
            if (!TryVerifyReference(reference, doc, payloadByRelativeUri, out error))
            {
                return false;
            }
        }

        return true;
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
        SignatureTrustPolicy? trustPolicy = null)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(payloadByRelativeUri);

        error = null;
        var signedXml = signature.SignedXmlCore;
        var sigEl = signedXml.GetXml() ?? throw new CryptographicException("Signature element is missing.");
        if (sigEl.OwnerDocument == null)
        {
            error = "Signature element is missing.";
            return false;
        }

        var doc = sigEl.OwnerDocument;

        if (signedXml.SignedInfo == null)
        {
            error = "SignedInfo is missing.";
            return false;
        }

        if (!TryVerifyReferenceDigests(signature, payloadByRelativeUri, out error))
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

    /// <summary>Attempts to verify reference.</summary>
    private static bool TryVerifyReference(
        Reference reference,
        XmlDocument document,
        IReadOnlyDictionary<string, byte[]> payloadByRelativeUri,
        out string? error)
    {
        error = null;
        var uri = reference.Uri ?? string.Empty;

        byte[] bytes;
        if (uri.StartsWith("#", StringComparison.Ordinal))
        {
            var id = uri[1..];
            var target = FindElementById(document, id);
            if (target == null)
            {
                error = $"Could not resolve reference URI '{uri}'.";
                return false;
            }

            bytes = ApplyTransforms(reference, target);
        }
        else
        {
            if (!payloadByRelativeUri.TryGetValue(uri, out var payload))
            {
                error = $"Missing payload for reference URI '{uri}'.";
                return false;
            }

            bytes = ApplyTransforms(reference, payload);
        }

        using var hashAlg = CreateHashAlgorithm(reference.DigestMethod);
        var expected = GetDigestBytes(reference);
        var actual = hashAlg.ComputeHash(bytes);
        if (!CryptographicOperations.FixedTimeEquals(actual, expected))
        {
            error = $"Digest mismatch for reference URI '{uri}'.";
            return false;
        }

        return true;
    }

    /// <summary>Applies transforms.</summary>
    private static byte[] ApplyTransforms(Reference reference, XmlElement element)
    {
        if (reference.TransformChain.Count == 0)
        {
            return CanonicalizeElementExcC14N(element);
        }

        var current = (object)WrapInOwnDocument(element);
        foreach (Transform transform in reference.TransformChain)
        {
            transform.LoadInput(current);
            current = transform.GetOutput(typeof(Stream)) ?? transform.GetOutput(typeof(XmlDocument))!;
            if (current is Stream s)
            {
                using var ms = new MemoryStream();
                s.CopyTo(ms);
                current = ms.ToArray();
            }
        }

        return current switch
        {
            byte[] b => b,
            XmlDocument d => CanonicalizeElementExcC14N(d.DocumentElement!),
            XmlElement e => CanonicalizeElementExcC14N(e),
            _ => throw new NotSupportedException("Transform output type is not supported."),
        };
    }

    /// <summary>Applies transforms.</summary>
    private static byte[] ApplyTransforms(Reference reference, byte[] payload)
    {
        if (reference.TransformChain.Count == 0)
        {
            return payload;
        }

        object current = payload;
        foreach (Transform transform in reference.TransformChain)
        {
            transform.LoadInput(current);
            var output = transform.GetOutput(typeof(Stream));
            if (output is not Stream stream)
            {
                throw new NotSupportedException("Transform chain over binary payload must yield a stream.");
            }

            using var ms = new MemoryStream();
            stream.CopyTo(ms);
            current = ms.ToArray();
        }

        return (byte[])current;
    }

    /// <summary>Wraps in own document.</summary>
    private static XmlDocument WrapInOwnDocument(XmlElement element)
    {
        var doc = new XmlDocument { PreserveWhitespace = false };
        doc.AppendChild(doc.ImportNode(element, deep: true));
        return doc;
    }

    /// <summary>Returns whether onicalize element exc c 14 n.</summary>
    private static byte[] CanonicalizeElementExcC14N(XmlElement element)
    {
        var transform = new XmlDsigExcC14NTransform();
        transform.LoadInput(WrapInOwnDocument(element));
        using var ms = (MemoryStream)transform.GetOutput(typeof(MemoryStream))!;
        return ms.ToArray();
    }

    /// <summary>Finds element by ID.</summary>
    private static XmlElement? FindElementById(XmlDocument doc, string id)
    {
        if (doc.DocumentElement == null)
        {
            return null;
        }

        if (TryMatch(doc.DocumentElement))
        {
            return doc.DocumentElement;
        }

        return Walk(doc.DocumentElement);

        XmlElement? Walk(XmlNode node)
        {
            foreach (XmlNode child in node.ChildNodes)
            {
                if (child is XmlElement el && TryMatch(el))
                {
                    return el;
                }

                if (child is XmlElement el2)
                {
                    var found = Walk(el2);
                    if (found != null)
                    {
                        return found;
                    }
                }
            }

            return null;
        }

        bool TryMatch(XmlElement el)
        {
            var attr = el.GetAttributeNode("Id", SignedXml.XmlDsigNamespaceUrl)
                       ?? el.GetAttributeNode("Id")
                       ?? el.Attributes?["Id"];
            return attr != null && attr.Value == id;
        }
    }

    /// <summary>Creates hash algorithm.</summary>
    private static HashAlgorithm CreateHashAlgorithm(string digestMethodUri) =>
        digestMethodUri switch
        {
            SignedXml.XmlDsigSHA256Url => SHA256.Create(),
            SignedXml.XmlDsigSHA384Url => SHA384.Create(),
            SignedXml.XmlDsigSHA512Url => SHA512.Create(),
            SignedXml.XmlDsigSHA1Url => SHA1.Create(),
            _ => throw new NotSupportedException($"Unsupported DigestMethod: {digestMethodUri}"),
        };

    /// <summary>Gets signature bytes from dom.</summary>
    private static byte[] GetSignatureBytesFromDom(XmlDocument document)
    {
        if (!SignatureValueReader.TryReadOctets(document, out var octets, out var error))
        {
            throw new CryptographicException(error);
        }

        return octets;
    }

    /// <summary>Gets digest bytes.</summary>
    private static byte[] GetDigestBytes(Reference reference)
    {
        object? v = reference.DigestValue;
        if (v == null)
        {
            throw new CryptographicException("DigestValue is empty.");
        }

        if (v is byte[] bytes)
        {
            return bytes;
        }

        if (v is string s)
        {
            return Convert.FromBase64String(s);
        }

        return Convert.FromBase64String(v.ToString() ?? string.Empty);
    }
}
