using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;
using eDocLib.Asic.Xades;

namespace eDocLib.Validation;

internal static partial class DetachedSignatureVerifier
{
    /// <summary>Imports the element into a standalone document for transform APIs.</summary>
    private static XmlDocument WrapInOwnDocument(XmlElement element)
    {
        var doc = new XmlDocument { PreserveWhitespace = false };
        doc.AppendChild(doc.ImportNode(element, deep: true));
        return doc;
    }

    /// <summary>Exclusive C14N of the element (UTF-8 octets used as transform input to digest).</summary>
    private static byte[] CanonicalizeElementExcC14N(XmlElement element)
    {
        var transform = new XmlDsigExcC14NTransform();
        transform.LoadInput(WrapInOwnDocument(element));
        using var ms = (MemoryStream)transform.GetOutput(typeof(MemoryStream))!;
        return ms.ToArray();
    }

    /// <summary>Finds the first element whose <c>Id</c> matches the fragment (XML-DSig same-document reference).</summary>
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

    private static HashAlgorithm CreateHashAlgorithm(string digestMethodUri) =>
        digestMethodUri switch
        {
            SignedXml.XmlDsigSHA256Url => SHA256.Create(),
            SignedXml.XmlDsigSHA384Url => SHA384.Create(),
            SignedXml.XmlDsigSHA512Url => SHA512.Create(),
            SignedXml.XmlDsigSHA1Url => SHA1.Create(),
            _ => throw new NotSupportedException($"Unsupported DigestMethod: {digestMethodUri}"),
        };

    private static byte[] GetSignatureBytesFromDom(XmlDocument document)
    {
        if (!SignatureValueReader.TryReadOctets(document, out var octets, out var error))
        {
            throw new CryptographicException(error);
        }

        return octets;
    }

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
            if (!Base64Bytes.TryFromBase64Trimmed(s, out var decoded))
            {
                throw new CryptographicException("DigestValue is not valid Base64.");
            }

            return decoded;
        }

        if (!Base64Bytes.TryFromBase64Trimmed(v.ToString() ?? string.Empty, out var decoded2))
        {
            throw new CryptographicException("DigestValue is not valid Base64.");
        }

        return decoded2;
    }
}
