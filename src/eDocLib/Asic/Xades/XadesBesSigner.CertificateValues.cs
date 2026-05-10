using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace eDocLib.Asic.Xades;

/// <summary>Partial class: <c>EncapsulatedX509Certificate</c> blocks under unsigned <c>CertificateValues</c>.</summary>
internal static partial class XadesBesSigner
{
    /// <summary>
    /// Appends <c>xades:CertificateValues</c> / <c>EncapsulatedX509Certificate</c> under <c>UnsignedSignatureProperties</c>
    /// (creates <c>UnsignedProperties</c> when missing). Used toward XAdES-LT-style material; does not add revocation data.
    /// </summary>
    public static void AppendUnsignedCertificateValues(XadesSignature signature, IEnumerable<X509Certificate2> certificates)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(certificates);

        var owner = signature.GetSignatureOwnerDocument();
        var xadesNs = XadesSignature.XadesNamespaceUrl;
        var unsignedSigProps = EnsureUnsignedSignatureProperties(owner);
        var certValues = FindOrCreateChild(owner, unsignedSigProps, "CertificateValues", xadesNs);

        foreach (var cert in certificates)
        {
            ArgumentNullException.ThrowIfNull(cert);
            var enc = owner.CreateElement(XadesSignature.XadesPrefix, "EncapsulatedX509Certificate", xadesNs);
            enc.InnerText = Convert.ToBase64String(cert.RawData);
            certValues.AppendChild(enc);
        }
    }

    /// <summary>Finds or create child.</summary>
    private static XmlElement FindOrCreateChild(XmlDocument doc, XmlElement parent, string localName, string ns)
    {
        foreach (XmlNode n in parent.ChildNodes)
        {
            if (n is XmlElement el && el.LocalName == localName && el.NamespaceURI == ns)
            {
                return el;
            }
        }

        var created = doc.CreateElement(XadesSignature.XadesPrefix, localName, ns);
        parent.AppendChild(created);
        return created;
    }
}
