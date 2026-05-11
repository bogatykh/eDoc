using System.Collections.Generic;
using System.Xml;
using eDocLib;

namespace eDocLib.Asic.Xades;

/// <summary>
/// Reads XAdES unsigned <c>CertificateValues</c> and <c>RevocationValues</c> (DER inside base64 elements).
/// </summary>
internal static class XadesUnsignedEmbeddedValues
{
    /// <summary>All <c>xades:EncapsulatedX509Certificate</c> under any <c>CertificateValues</c> in document order.</summary>
    public static IReadOnlyList<byte[]> ReadEncapsulatedX509Certificates(XmlDocument ownerDocument)
    {
        ArgumentNullException.ThrowIfNull(ownerDocument);
        return ReadBase64Children(ownerDocument, "CertificateValues", "EncapsulatedX509Certificate");
    }

    /// <summary>
    /// DER PKCS#7 blobs from <c>xades:CertificateValues</c> / <c>OtherCertificate</c> / <c>EncapsulatedPKIData</c>
    /// (document order).
    /// </summary>
    public static IReadOnlyList<byte[]> ReadEncapsulatedPkcs7CertificateData(XmlDocument ownerDocument)
    {
        ArgumentNullException.ThrowIfNull(ownerDocument);
        return ReadBase64ElementsXPath(
            ownerDocument,
            "//xades:CertificateValues/xades:OtherCertificate/xades:EncapsulatedPKIData");
    }

    /// <summary>All <c>xades:EncapsulatedOCSPValue</c> under <c>RevocationValues</c> / <c>OCSPValues</c>.</summary>
    public static IReadOnlyList<byte[]> ReadEncapsulatedOcspResponses(XmlDocument ownerDocument)
    {
        ArgumentNullException.ThrowIfNull(ownerDocument);
        return ReadBase64UnderPath(ownerDocument, "RevocationValues", "OCSPValues", "EncapsulatedOCSPValue");
    }

    /// <summary>All <c>xades:EncapsulatedCRLValue</c> under <c>RevocationValues</c> / <c>CRLValues</c>.</summary>
    public static IReadOnlyList<byte[]> ReadEncapsulatedCrls(XmlDocument ownerDocument)
    {
        ArgumentNullException.ThrowIfNull(ownerDocument);
        return ReadBase64UnderPath(ownerDocument, "RevocationValues", "CRLValues", "EncapsulatedCRLValue");
    }

    /// <summary>
    /// All <c>xades:EncapsulatedTimeStamp</c> elements in document order (DER inside Base64), including
    /// <c>SignatureTimeStamp</c> and archive timestamp blocks when present.
    /// </summary>
    public static IReadOnlyList<byte[]> ReadEncapsulatedTimeStamps(XmlDocument ownerDocument)
    {
        ArgumentNullException.ThrowIfNull(ownerDocument);
        return ReadBase64ElementsXPath(ownerDocument, "//xades:EncapsulatedTimeStamp");
    }

    /// <summary>
    /// <c>xades:EncapsulatedTimeStamp</c> under <c>xades:SignatureTimeStamp</c> only (XAdES-T), document order — excludes archive tokens.
    /// </summary>
    public static IReadOnlyList<byte[]> ReadEncapsulatedSignatureTimeStamps(XmlDocument ownerDocument)
    {
        ArgumentNullException.ThrowIfNull(ownerDocument);
        return ReadBase64ElementsXPath(ownerDocument, SignatureTimeStampEncapsulatedTimeStampXPath);
    }

    /// <summary>
    /// Whether the document has at least one decodable <see cref="ReadEncapsulatedSignatureTimeStamps"/> payload (avoids building a list when only presence is needed).
    /// </summary>
    public static bool HasEncapsulatedSignatureTimeStamp(XmlDocument ownerDocument)
    {
        ArgumentNullException.ThrowIfNull(ownerDocument);
        var nsm = XadesXmlNamespaces.ForXades(ownerDocument.NameTable);
        var nodes = ownerDocument.SelectNodes(SignatureTimeStampEncapsulatedTimeStampXPath, nsm);
        if (nodes is null)
        {
            return false;
        }

        foreach (XmlNode n in nodes)
        {
            if (n is XmlElement el && Base64Bytes.TryFromBase64Trimmed(el.InnerText, out _))
            {
                return true;
            }
        }

        return false;
    }

    private const string SignatureTimeStampEncapsulatedTimeStampXPath = "//xades:SignatureTimeStamp/xades:EncapsulatedTimeStamp";

    /// <summary>
    /// <c>xades:EncapsulatedTimeStamp</c> elements that are direct children of <c>xades:ArchiveTimeStamp</c> (DER), document order.
    /// </summary>
    public static IReadOnlyList<byte[]> ReadEncapsulatedArchiveTimeStamps(XmlDocument ownerDocument)
    {
        ArgumentNullException.ThrowIfNull(ownerDocument);
        return ReadBase64ElementsXPath(ownerDocument, "//xades:ArchiveTimeStamp/xades:EncapsulatedTimeStamp");
    }

    /// <summary>Reads base 64 children.</summary>
    private static IReadOnlyList<byte[]> ReadBase64Children(XmlDocument doc, string containerLocalName, string childLocalName)
    {
        var nsm = XadesXmlNamespaces.ForXades(doc.NameTable);
        var containers = doc.SelectNodes($"//xades:{containerLocalName}", nsm);
        if (containers == null || containers.Count == 0)
        {
            return [];
        }

        var list = new List<byte[]>(containers.Count);
        foreach (XmlNode c in containers)
        {
            if (c is not XmlElement container)
            {
                continue;
            }

            foreach (XmlNode n in container.ChildNodes)
            {
                if (n is XmlElement el
                    && el.LocalName == childLocalName
                    && el.NamespaceURI == XadesSignature.XadesNamespaceUrl)
                {
                    if (Base64Bytes.TryFromBase64Trimmed(el.InnerText, out var der))
                    {
                        list.Add(der);
                    }
                }
            }
        }

        return list;
    }

    /// <summary>Reads base 64 under path.</summary>
    private static IReadOnlyList<byte[]> ReadBase64UnderPath(
        XmlDocument doc,
        string level1,
        string level2,
        string leafLocalName) =>
        ReadBase64ElementsXPath(doc, $"//xades:{level1}/xades:{level2}/xades:{leafLocalName}");

    /// <summary>Reads base 64 elements x path.</summary>
    private static IReadOnlyList<byte[]> ReadBase64ElementsXPath(XmlDocument doc, string xpath)
    {
        var nsm = XadesXmlNamespaces.ForXades(doc.NameTable);
        var nodes = doc.SelectNodes(xpath, nsm);
        if (nodes == null || nodes.Count == 0)
        {
            return [];
        }

        var list = new List<byte[]>(nodes.Count);
        foreach (XmlNode n in nodes)
        {
            if (n is XmlElement el && Base64Bytes.TryFromBase64Trimmed(el.InnerText, out var der))
            {
                list.Add(der);
            }
        }

        return list;
    }

}
