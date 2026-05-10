using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace eDocLib.Asic.Xades;

/// <summary>Detached XML-DSig signature with XAdES qualifying properties, hosted in an ASiC-E <c>META-INF</c> entry.</summary>
internal class XadesSignature : ISignature
{
    /// <summary>URI for <c>xades:SignedProperties</c> <c>Object</c> references.</summary>
    public const string XmlDsigSignatureProperties = "http://uri.etsi.org/01903#SignedProperties";

    /// <summary>Legacy Proof-of-Approval URI referenced by some profiles.</summary>
    public const string XadesProofOfApproval = "http://uri.etsi.org/01903/v1.2.2#ProofOfApproval";

    /// <summary>Preferred XML prefix for XAdES elements.</summary>
    public const string XadesPrefix = "xades";

    /// <summary>Default XAdES XML namespace for elements produced by this library.</summary>
    public const string XadesNamespaceUrl = "http://uri.etsi.org/01903/v1.3.2#";

    /// <summary>Stores the signed XML.</summary>
    private readonly SignedXml _signedXml;

    /// <summary>Initializes a new XAdES signature instance.</summary>
    public XadesSignature()
    {
        _signedXml = new SignedXml();
    }

    /// <summary>Parses <paramref name="document"/> and loads the first <c>ds:Signature</c> element.</summary>
    public XadesSignature(XmlDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        var el = FindSignatureElement(document)
                 ?? throw new ArgumentException("No XML-DSig Signature element.", nameof(document));
        _signedXml = new SignedXml(document);
        _signedXml.LoadXml(el);
    }

    /// <summary>Stores the signed XML core.</summary>
    internal SignedXml SignedXmlCore => _signedXml;

    /// <summary>Full signature XML document (root element is <c>ds:Signature</c>).</summary>
    public XmlDocument GetSignatureOwnerDocument() =>
        _signedXml.GetXml()?.OwnerDocument ?? throw new InvalidOperationException("Signature is not attached to a document.");

    /// <summary>Stores the ID.</summary>
    /// <inheritdoc />
    public string Id => _signedXml.Signature?.Id ?? string.Empty;

    /// <summary>Stores the signature method.</summary>
    /// <inheritdoc />
    public string SignatureMethod => _signedXml.SignatureMethod ?? string.Empty;

    /// <inheritdoc />
    public X509Certificate? SigningCertificate
    {
        get
        {
            var x509Data = _signedXml.KeyInfo.OfType<KeyInfoX509Data>().SingleOrDefault();
            if (x509Data?.Certificates == null || x509Data.Certificates.Count == 0)
            {
                return null;
            }

            return x509Data.Certificates[0] as X509Certificate2;
        }
    }

    /// <summary>Stores the signer roles.</summary>
    /// <inheritdoc />
    public IReadOnlyCollection<string> SignerRoles => ParseSignerRoles(_signedXml);

    /// <summary>Stores the signature production place.</summary>
    /// <inheritdoc />
    public SignatureProductionPlace? SignatureProductionPlace => ParseSignatureProductionPlace(_signedXml);

    /// <summary>Claimed XAdES <c>SigningTime</c> from signed properties, when present and parseable.</summary>
    public DateTimeOffset? ClaimedSigningTime => TryReadClaimedSigningTime(GetSignatureOwnerDocument());

    /// <summary>Raw octets inside <c>ds:SignatureValue</c> (Base64-decoded).</summary>
    /// <exception cref="InvalidOperationException">Element is missing or not valid Base64.</exception>
    public byte[] GetSignatureValueOctets()
    {
        var owner = GetSignatureOwnerDocument();
        var nodes = owner.GetElementsByTagName("SignatureValue", SignedXml.XmlDsigNamespaceUrl);
        if (nodes.Count == 0 || nodes[0] is not XmlElement el)
        {
            throw new InvalidOperationException("ds:SignatureValue is missing.");
        }

        var text = el.InnerText.Trim();
        if (text.Length == 0)
        {
            throw new InvalidOperationException("ds:SignatureValue is empty.");
        }

        try
        {
            return Convert.FromBase64String(text);
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException("ds:SignatureValue is not valid Base64.", ex);
        }
    }

    /// <summary>DER of each <c>xades:EncapsulatedX509Certificate</c> under unsigned <c>CertificateValues</c>.</summary>
    public IReadOnlyList<byte[]> UnsignedEncapsulatedX509Der =>
        XadesUnsignedEmbeddedValues.ReadEncapsulatedX509Certificates(GetSignatureOwnerDocument());

    /// <summary>
    /// PKCS#7 certificate bundles from <c>xades:OtherCertificate</c> / <c>EncapsulatedPKIData</c> under unsigned
    /// <c>CertificateValues</c>.
    /// </summary>
    public IReadOnlyList<byte[]> UnsignedEncapsulatedPkcs7Der =>
        XadesUnsignedEmbeddedValues.ReadEncapsulatedPkcs7CertificateData(GetSignatureOwnerDocument());

    /// <summary>DER OCSP responses from unsigned <c>RevocationValues</c> / <c>OCSPValues</c>.</summary>
    public IReadOnlyList<byte[]> UnsignedEncapsulatedOcspDer =>
        XadesUnsignedEmbeddedValues.ReadEncapsulatedOcspResponses(GetSignatureOwnerDocument());

    /// <summary>DER CRLs from unsigned <c>RevocationValues</c> / <c>CRLValues</c>.</summary>
    public IReadOnlyList<byte[]> UnsignedEncapsulatedCrlDer =>
        XadesUnsignedEmbeddedValues.ReadEncapsulatedCrls(GetSignatureOwnerDocument());

    /// <summary>DER of each RFC 3161 token under <c>xades:ArchiveTimeStamp</c> / <c>EncapsulatedTimeStamp</c> (XAdES-A / LTA).</summary>
    public IReadOnlyList<byte[]> UnsignedEncapsulatedArchiveTimeStampDer =>
        XadesUnsignedEmbeddedValues.ReadEncapsulatedArchiveTimeStamps(GetSignatureOwnerDocument());

    /// <summary>Writes to.</summary>
    /// <inheritdoc />
    public virtual void WriteTo(Stream stream)
    {
        var owner = GetSignatureOwnerDocument();
        var root = owner.DocumentElement ?? throw new InvalidOperationException("Signature document has no root.");

        // SignedXml.GetXml() can be a detached fragment that does not reflect live DOM edits (e.g. SignatureValue).
        // When the whole document is one ds:Signature, serialize the owner — the authoritative tree.
        string xml;
        if (root.LocalName == "Signature" && root.NamespaceURI == SignedXml.XmlDsigNamespaceUrl)
        {
            xml = owner.OuterXml;
        }
        else
        {
            var sig = _signedXml.GetXml() ?? throw new InvalidOperationException("Signature XML is not available.");
            var doc = XadesXmlDocument.Empty();
            doc.AppendChild(doc.ImportNode(sig, deep: true));
            xml = doc.OuterXml;
        }

        var enc = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
        var bytes = enc.GetBytes(xml);
        stream.Write(bytes, 0, bytes.Length);
    }

    /// <summary>Finds signature element.</summary>
    internal static XmlElement? FindSignatureElement(XmlDocument document)
    {
        if (document.DocumentElement == null)
        {
            return null;
        }

        var root = document.DocumentElement;
        if (root.LocalName == "Signature" && root.NamespaceURI == SignedXml.XmlDsigNamespaceUrl)
        {
            return root;
        }

        return document.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl)
            .OfType<XmlElement>()
            .FirstOrDefault();
    }

    /// <summary>Parses signer roles.</summary>
    private static IReadOnlyCollection<string> ParseSignerRoles(SignedXml signedXml)
    {
        var doc = signedXml.GetXml()?.OwnerDocument;
        if (doc == null)
        {
            return [];
        }

        var nsm = XadesXmlNamespaces.ForXadesAndDs(doc.NameTable);

        var roles = doc.SelectNodes("//xades:ClaimedRole", nsm);
        if (roles == null || roles.Count == 0)
        {
            return [];
        }

        var list = new List<string>();
        foreach (XmlNode n in roles)
        {
            if (!string.IsNullOrWhiteSpace(n.InnerText))
            {
                list.Add(n.InnerText.Trim());
            }
        }

        return list;
    }

    /// <summary>Parses signature production place.</summary>
    private static SignatureProductionPlace? ParseSignatureProductionPlace(SignedXml signedXml)
    {
        var doc = signedXml.GetXml()?.OwnerDocument;
        if (doc == null)
        {
            return null;
        }

        var nsm = XadesXmlNamespaces.ForXadesAndDs(doc.NameTable);

        var place = doc.SelectSingleNode("//xades:SignatureProductionPlace", nsm) as XmlElement;
        if (place == null)
        {
            return null;
        }

        static string? T(XmlElement root, string localName)
        {
            foreach (XmlNode c in root.ChildNodes)
            {
                if (c is XmlElement el && el.LocalName == localName && el.NamespaceURI == XadesNamespaceUrl)
                {
                    var t = el.InnerText.Trim();
                    return t.Length == 0 ? null : t;
                }
            }

            return null;
        }

        var city = T(place, "City");
        var state = T(place, "StateOrProvince");
        var postal = T(place, "PostalCode");
        var country = T(place, "CountryName");
        if (city == null && state == null && postal == null && country == null)
        {
            return null;
        }

        return new SignatureProductionPlace(city, state, postal, country);
    }

    /// <summary>Attempts to read claimed signing time.</summary>
    private static DateTimeOffset? TryReadClaimedSigningTime(XmlDocument doc)
    {
        var nsm = XadesXmlNamespaces.ForXades(doc.NameTable);
        var node = doc.SelectSingleNode("//xades:SigningTime", nsm);
        if (node == null || string.IsNullOrWhiteSpace(node.InnerText))
        {
            return null;
        }

        return DateTimeOffset.TryParse(node.InnerText.Trim(), out var t) ? t : null;
    }
}
