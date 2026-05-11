using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using eDocLib;
using eDocLib.Asic.Container;

namespace eDocLib.Asic.Xades;

/// <summary>
/// Builds XAdES-BES detached signatures for ASiC-E payloads (one <c>ds:Reference</c> per data file by relative path).
/// Strategy: explicit XML-DSig construction; RSA-SHA256 (default) or RSA-SHA384 (optional), or ECDSA-SHA256 (P-256) / ECDSA-SHA384 (P-384); XAdES <c>SigningTime</c> in <c>QualifyingProperties</c>.
/// Call <c>SignWithTimestampAsync</c> with an <see cref="eDocLib.Timestamp.ITimestampProvider"/> or <see cref="eDocLib.Timestamp.TimestampResponderRegistry"/> to produce XAdES-T (<c>SignatureTimeStamp</c> over SHA-256 of raw <c>SignatureValue</c> bytes).
/// </summary>
internal static partial class XadesBesSigner
{
    private const string DsNs = SignedXml.XmlDsigNamespaceUrl;

    /// <summary>
    /// Builds a BES signature document with placeholder <c>SignatureValue</c>. Does not require a private key on
    /// <paramref name="signerCertificate"/> (public certificate is enough for <c>KeyInfo</c>).
    /// Sign <see cref="XadesBesPreparedSignature.GetSignableBytes"/> externally, then <see cref="XadesBesPreparedSignature.Complete"/>.
    /// </summary>
    public static XadesBesPreparedSignature PrepareSign(
        IEnumerable<IDataFile> dataFiles,
        X509Certificate2 signerCertificate,
        DateTimeOffset signingTime,
        string signatureId = "sig-1",
        string signedPropertiesId = "SignedProperties-1",
        IReadOnlyList<string>? signerRoles = null,
        SignatureProductionPlace? productionPlace = null,
        XadesRsaDigestPreference rsaDigestPreference = XadesRsaDigestPreference.Sha256)
    {
        ArgumentNullException.ThrowIfNull(dataFiles);
        ArgumentNullException.ThrowIfNull(signerCertificate);

        var profile = XadesSigningProfile.FromCertificate(signerCertificate, rsaDigestPreference);
        var fileEntries = ReadPayloadEntries(dataFiles);
        var normalized = CreateNormalizedBesSignatureDom(
            fileEntries,
            signerCertificate,
            signingTime,
            signatureId,
            signedPropertiesId,
            signerRoles,
            productionPlace,
            profile);
        return new XadesBesPreparedSignature(normalized, profile);
    }

    /// <summary>
    /// Creates a detached signature covering all <paramref name="dataFiles"/> by <see cref="IDataFile.Name"/> URI.
    /// Streams are read from the current position to end; positions are not reset.
    /// </summary>
    /// <param name="dataFiles">Payload files to reference from the detached signature.</param>
    /// <param name="signerCertificate">Certificate with private key used to sign <c>SignedInfo</c>.</param>
    /// <param name="signingTime">UTC signing time written into XAdES signed properties.</param>
    /// <param name="signatureId">Identifier assigned to the <c>ds:Signature</c> element.</param>
    /// <param name="signedPropertiesId">Identifier assigned to the XAdES signed properties element.</param>
    /// <param name="signerRoles">Optional XAdES <c>ClaimedRole</c> strings (placed under <c>SignerRole</c>).</param>
    /// <param name="productionPlace">Optional XAdES <c>SignatureProductionPlace</c>.</param>
    /// <param name="rsaDigestPreference">Digest algorithm preference for RSA certificates.</param>
    internal static AsicSignature Sign(
        IEnumerable<IDataFile> dataFiles,
        X509Certificate2 signerCertificate,
        DateTimeOffset signingTime,
        string signatureId = "sig-1",
        string signedPropertiesId = "SignedProperties-1",
        IReadOnlyList<string>? signerRoles = null,
        SignatureProductionPlace? productionPlace = null,
        XadesRsaDigestPreference rsaDigestPreference = XadesRsaDigestPreference.Sha256)
    {
        ArgumentNullException.ThrowIfNull(signerCertificate);
        if (!signerCertificate.HasPrivateKey)
        {
            throw new ArgumentException("Certificate must include a private key.", nameof(signerCertificate));
        }

        var prep = PrepareSign(
            dataFiles,
            signerCertificate,
            signingTime,
            signatureId,
            signedPropertiesId,
            signerRoles,
            productionPlace,
            rsaDigestPreference);
        var signable = prep.GetSignableBytes();
        var signatureBytes = SignSignedInfoDigest(signerCertificate, prep.SigningProfile, signable);
        return (AsicSignature)prep.Complete(signatureBytes);
    }

    private static List<(string Name, byte[] Payload)> ReadPayloadEntries(IEnumerable<IDataFile> dataFiles)
    {
        return dataFiles.Select(df =>
        {
            ArgumentException.ThrowIfNullOrEmpty(df.Name);
            using var ms = new MemoryStream();
            df.Stream.CopyTo(ms);
            return (df.Name, Payload: ms.ToArray());
        }).ToList();
    }

    /// <summary>Creates normalized bes signature dom.</summary>
    private static XmlDocument CreateNormalizedBesSignatureDom(
        List<(string Name, byte[] Payload)> fileEntries,
        X509Certificate2 signerCertificate,
        DateTimeOffset signingTime,
        string signatureId,
        string signedPropertiesId,
        IReadOnlyList<string>? signerRoles,
        SignatureProductionPlace? productionPlace,
        XadesSigningProfile profile)
    {
        var doc = XadesXmlDocument.Empty();

        var signatureEl = doc.CreateElement("ds", "Signature", DsNs);
        signatureEl.SetAttribute("Id", signatureId);
        doc.AppendChild(signatureEl);

        var signedInfo = doc.CreateElement("ds", "SignedInfo", DsNs);
        signatureEl.AppendChild(signedInfo);

        var canon = doc.CreateElement("ds", "CanonicalizationMethod", DsNs);
        canon.SetAttribute("Algorithm", XadesSignatureAlgorithms.ExclusiveCanonicalXml);
        signedInfo.AppendChild(canon);

        var sigMethod = doc.CreateElement("ds", "SignatureMethod", DsNs);
        sigMethod.SetAttribute("Algorithm", profile.SignatureMethodUri);
        signedInfo.AppendChild(sigMethod);

        foreach (var (name, payload) in fileEntries)
        {
            signedInfo.AppendChild(CreateDataReference(doc, name, payload, profile.SignedInfoHashAlgorithm, profile.DigestMethodUri));
        }

        var sigValue = doc.CreateElement("ds", "SignatureValue", DsNs);
        sigValue.InnerText = " ";
        signatureEl.AppendChild(sigValue);

        var keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(signerCertificate));
        var keyInfoXml = keyInfo.GetXml();
        var importedKeyInfo = doc.ImportNode(keyInfoXml, deep: true);
        signatureEl.AppendChild(importedKeyInfo);

        var qualifying = BuildQualifyingProperties(
            doc,
            signerCertificate,
            signingTime,
            signedPropertiesId,
            signatureId,
            signerRoles,
            productionPlace,
            profile);
        var objectEl = doc.CreateElement("ds", "Object", DsNs);
        objectEl.AppendChild(qualifying);
        signatureEl.AppendChild(objectEl);

        var signedPropsDigestDraft = DigestSignedPropertiesInPlace(doc, signedPropertiesId, profile.SignedInfoHashAlgorithm);
        signedInfo.AppendChild(CreateSignedPropertiesReference(doc, signedPropertiesId, signedPropsDigestDraft, profile.DigestMethodUri));

        // Clone once so SignedProperties digest + Reference DigestValue are computed on the same infoset shape
        // verifiers will see after deployment (namespace/default-attribute normalization via ImportNode, not string round-trip).
        var stable = XadesXmlDocument.Clone(doc);
        var signedPropsDigest = DigestSignedPropertiesInPlace(stable, signedPropertiesId, profile.SignedInfoHashAlgorithm);
        SetDigestValueForReferenceUri(stable, "#" + signedPropertiesId, signedPropsDigest);

        GetRequiredElement(stable, "SignatureValue", DsNs).InnerText = " ";
        return stable;
    }

    /// <summary>Digests the SignedProperties element in place.</summary>
    private static byte[] DigestSignedPropertiesInPlace(XmlDocument doc, string signedPropertiesId, HashAlgorithmName digestAlgorithm)
    {
        var nodes = doc.GetElementsByTagName("SignedProperties", XadesSignature.XadesNamespaceUrl);
        for (var i = 0; i < nodes.Count; i++)
        {
            if (nodes[i] is XmlElement signedProps && signedProps.GetAttribute("Id") == signedPropertiesId)
            {
                return HashPayload(CanonicalizeElement(signedProps), digestAlgorithm);
            }
        }

        throw new InvalidOperationException("SignedProperties element not found after build.");
    }

    /// <summary>Hashes payload.</summary>
    private static byte[] HashPayload(byte[] payload, HashAlgorithmName digestAlgorithm) =>
        digestAlgorithm.Name switch
        {
            nameof(SHA256) => SHA256.HashData(payload),
            nameof(SHA384) => SHA384.HashData(payload),
            nameof(SHA512) => SHA512.HashData(payload),
            _ => throw new ArgumentOutOfRangeException(nameof(digestAlgorithm), digestAlgorithm, "Only SHA-256, SHA-384, and SHA-512 are supported."),
        };

    /// <summary>Signs signed info digest.</summary>
    internal static byte[] SignSignedInfoDigest(X509Certificate2 certificate, XadesSigningProfile profile, byte[] signableDigest) =>
        profile.KeyKind switch
        {
            XadesKeyKind.Rsa => SignRsa(certificate, signableDigest, profile.SignedInfoHashAlgorithm),
            XadesKeyKind.Ecdsa => SignEcdsa(certificate, signableDigest, profile.SignedInfoHashAlgorithm),
            _ => throw new ArgumentOutOfRangeException(nameof(profile), profile.KeyKind, "Unknown key kind."),
        };

    /// <summary>Signs RSA.</summary>
    private static byte[] SignRsa(X509Certificate2 certificate, byte[] signable, HashAlgorithmName hash)
    {
        using var rsa = certificate.GetRSAPrivateKey()
                        ?? throw new InvalidOperationException("RSA private key is not available on the certificate.");
        return rsa.SignData(signable, hash, RSASignaturePadding.Pkcs1);
    }

    /// <summary>Signs ECDSA.</summary>
    private static byte[] SignEcdsa(X509Certificate2 certificate, byte[] signable, HashAlgorithmName hash)
    {
        using var ec = certificate.GetECDsaPrivateKey()
                       ?? throw new InvalidOperationException("ECDsa private key is not available on the certificate.");
        return ec.SignData(signable, hash, DSASignatureFormat.Rfc3279DerSequence);
    }

    /// <summary>Sets digest value for reference URI.</summary>
    private static void SetDigestValueForReferenceUri(XmlDocument doc, string uri, byte[] digest)
    {
        var refs = doc.GetElementsByTagName("Reference", DsNs);
        for (var i = 0; i < refs.Count; i++)
        {
            if (refs[i] is not XmlElement reference || reference.GetAttribute("URI") != uri)
            {
                continue;
            }

            var digestValues = reference.GetElementsByTagName("DigestValue", DsNs);
            if (digestValues.Count == 0)
            {
                throw new InvalidOperationException("DigestValue missing on SignedProperties reference.");
            }

            ((XmlElement)digestValues[0]!).InnerText = Convert.ToBase64String(digest);
            return;
        }

        throw new InvalidOperationException($"Reference with URI {uri} not found.");
    }

    /// <summary>Gets required element.</summary>
    private static XmlElement GetRequiredElement(XmlDocument doc, string localName, string ns)
    {
        var nodes = doc.GetElementsByTagName(localName, ns);
        if (nodes.Count == 0)
        {
            throw new InvalidOperationException($"Missing element {localName}.");
        }

        return (XmlElement)nodes[0]!;
    }

    /// <summary>Creates data reference.</summary>
    private static XmlElement CreateDataReference(XmlDocument doc, string relativeUri, byte[] payload, HashAlgorithmName digestAlgorithm, string digestMethodUri)
    {
        var hash = HashPayload(payload, digestAlgorithm);
        var reference = doc.CreateElement("ds", "Reference", DsNs);
        reference.SetAttribute("URI", relativeUri);

        var digestMethod = doc.CreateElement("ds", "DigestMethod", DsNs);
        digestMethod.SetAttribute("Algorithm", digestMethodUri);
        reference.AppendChild(digestMethod);

        var digestValue = doc.CreateElement("ds", "DigestValue", DsNs);
        digestValue.InnerText = Convert.ToBase64String(hash);
        reference.AppendChild(digestValue);

        return reference;
    }

    /// <summary>Builds qualifying properties.</summary>
    private static XmlElement BuildQualifyingProperties(
        XmlDocument doc,
        X509Certificate2 signerCertificate,
        DateTimeOffset signingTime,
        string signedPropertiesId,
        string signatureId,
        IReadOnlyList<string>? signerRoles,
        SignatureProductionPlace? productionPlace,
        XadesSigningProfile profile)
    {
        var qualifying = doc.CreateElement(XadesSignature.XadesPrefix, "QualifyingProperties", XadesSignature.XadesNamespaceUrl);
        qualifying.SetAttribute($"xmlns:{XadesSignature.XadesPrefix}", XadesSignature.XadesNamespaceUrl);
        qualifying.SetAttribute("Target", "#" + signatureId);

        var signedProps = doc.CreateElement(XadesSignature.XadesPrefix, "SignedProperties", XadesSignature.XadesNamespaceUrl);
        signedProps.SetAttribute("Id", signedPropertiesId);
        qualifying.AppendChild(signedProps);

        var signedSigProps = doc.CreateElement(XadesSignature.XadesPrefix, "SignedSignatureProperties", XadesSignature.XadesNamespaceUrl);
        signedProps.AppendChild(signedSigProps);

        var signingTimeEl = doc.CreateElement(XadesSignature.XadesPrefix, "SigningTime", XadesSignature.XadesNamespaceUrl);
        signingTimeEl.InnerText = signingTime.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ");
        signedSigProps.AppendChild(signingTimeEl);

        AppendSigningCertificate(doc, signedSigProps, signerCertificate, profile);

        if (productionPlace is not null)
        {
            AppendProductionPlace(doc, signedSigProps, productionPlace);
        }

        if (signerRoles is { Count: > 0 })
        {
            var signerRole = doc.CreateElement(XadesSignature.XadesPrefix, "SignerRole", XadesSignature.XadesNamespaceUrl);
            signedSigProps.AppendChild(signerRole);
            var claimedRoles = doc.CreateElement(XadesSignature.XadesPrefix, "ClaimedRoles", XadesSignature.XadesNamespaceUrl);
            signerRole.AppendChild(claimedRoles);
            foreach (var role in signerRoles)
            {
                if (string.IsNullOrWhiteSpace(role))
                {
                    continue;
                }

                var claimed = doc.CreateElement(XadesSignature.XadesPrefix, "ClaimedRole", XadesSignature.XadesNamespaceUrl);
                claimed.InnerText = role.Trim();
                claimedRoles.AppendChild(claimed);
            }
        }

        return qualifying;
    }

    /// <summary>Appends signing certificate.</summary>
    private static void AppendSigningCertificate(XmlDocument doc, XmlElement signedSigProps, X509Certificate2 signerCertificate, XadesSigningProfile profile)
    {
        var sc = doc.CreateElement(XadesSignature.XadesPrefix, "SigningCertificate", XadesSignature.XadesNamespaceUrl);
        var certEl = doc.CreateElement(XadesSignature.XadesPrefix, "Cert", XadesSignature.XadesNamespaceUrl);
        sc.AppendChild(certEl);

        var certDigest = doc.CreateElement(XadesSignature.XadesPrefix, "CertDigest", XadesSignature.XadesNamespaceUrl);
        certEl.AppendChild(certDigest);
        var dm = doc.CreateElement("ds", "DigestMethod", DsNs);
        dm.SetAttribute("Algorithm", profile.DigestMethodUri);
        certDigest.AppendChild(dm);
        var dv = doc.CreateElement("ds", "DigestValue", DsNs);
        dv.InnerText = Convert.ToBase64String(HashPayload(signerCertificate.RawData, profile.SignedInfoHashAlgorithm));
        certDigest.AppendChild(dv);

        var issuerSerial = doc.CreateElement(XadesSignature.XadesPrefix, "IssuerSerial", XadesSignature.XadesNamespaceUrl);
        certEl.AppendChild(issuerSerial);
        var issuerName = doc.CreateElement("ds", "X509IssuerName", DsNs);
        issuerName.InnerText = signerCertificate.Issuer;
        issuerSerial.AppendChild(issuerName);
        var serial = doc.CreateElement("ds", "X509SerialNumber", DsNs);
        serial.InnerText = X509IssuerSerialXmlFormatter.SerialNumberDecimalString(signerCertificate);
        issuerSerial.AppendChild(serial);

        signedSigProps.AppendChild(sc);
    }

    /// <summary>Appends production place.</summary>
    private static void AppendProductionPlace(XmlDocument doc, XmlElement signedSigProps, SignatureProductionPlace place)
    {
        static void AddIfPresent(XmlDocument d, XmlElement parent, string localName, string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return;
            }

            var el = d.CreateElement(XadesSignature.XadesPrefix, localName, XadesSignature.XadesNamespaceUrl);
            el.InnerText = value.Trim();
            parent.AppendChild(el);
        }

        var wrap = doc.CreateElement(XadesSignature.XadesPrefix, "SignatureProductionPlace", XadesSignature.XadesNamespaceUrl);
        AddIfPresent(doc, wrap, "City", place.City);
        AddIfPresent(doc, wrap, "StateOrProvince", place.StateOrProvince);
        AddIfPresent(doc, wrap, "PostalCode", place.PostalCode);
        AddIfPresent(doc, wrap, "CountryName", place.CountryName);
        if (wrap.ChildNodes.Count > 0)
        {
            signedSigProps.AppendChild(wrap);
        }
    }

    /// <summary>Creates signed properties reference.</summary>
    private static XmlElement CreateSignedPropertiesReference(XmlDocument doc, string signedPropertiesId, byte[] digest, string digestMethodUri)
    {
        var reference = doc.CreateElement("ds", "Reference", DsNs);
        reference.SetAttribute("URI", "#" + signedPropertiesId);
        reference.SetAttribute("Type", XadesSignature.XmlDsigSignatureProperties);

        var transforms = doc.CreateElement("ds", "Transforms", DsNs);
        reference.AppendChild(transforms);

        var exc = doc.CreateElement("ds", "Transform", DsNs);
        exc.SetAttribute("Algorithm", XadesSignatureAlgorithms.ExclusiveCanonicalXml);
        transforms.AppendChild(exc);

        var digestMethod = doc.CreateElement("ds", "DigestMethod", DsNs);
        digestMethod.SetAttribute("Algorithm", digestMethodUri);
        reference.AppendChild(digestMethod);

        var digestValue = doc.CreateElement("ds", "DigestValue", DsNs);
        digestValue.InnerText = Convert.ToBase64String(digest);
        reference.AppendChild(digestValue);

        return reference;
    }

    /// <summary>Returns whether onicalize element.</summary>
    private static byte[] CanonicalizeElement(XmlElement element)
    {
        var transform = new XmlDsigExcC14NTransform();
        var nsDoc = XadesXmlDocument.Empty();
        nsDoc.AppendChild(nsDoc.ImportNode(element, deep: true));
        transform.LoadInput(nsDoc);
        using var ms = (MemoryStream)transform.GetOutput(typeof(MemoryStream))!;
        return ms.ToArray();
    }
}
