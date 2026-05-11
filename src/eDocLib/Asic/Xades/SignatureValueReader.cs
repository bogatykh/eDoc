using System.Security.Cryptography.Xml;
using System.Xml;

namespace eDocLib.Asic.Xades;

/// <summary>
/// Reads or writes the Base64-encoded body of <c>ds:SignatureValue</c> in an XML-DSig / XAdES document.
/// Centralises element lookup that previously existed in <c>XadesSignature</c>,
/// <c>SignatureTimestampVerifier</c>, <c>DetachedSignatureVerifier</c>, <c>XadesBesSigner.Timestamp</c>,
/// and <c>XadesBesPreparedSignature</c>.
/// </summary>
internal static class SignatureValueReader
{
    /// <summary>
    /// Reads the first <c>ds:SignatureValue</c> element from <paramref name="document"/> and Base64-decodes its inner text.
    /// </summary>
    /// <param name="document">XML document containing the signature.</param>
    /// <param name="octets">Decoded octets on success.</param>
    /// <param name="error">Human-readable failure reason; <c>null</c> on success.</param>
    public static bool TryReadOctets(XmlDocument document, out byte[] octets, out string? error)
    {
        ArgumentNullException.ThrowIfNull(document);
        octets = [];
        if (!TryFindElement(document, out var el))
        {
            error = "ds:SignatureValue is missing.";
            return false;
        }

        var text = el.InnerText.Trim();
        if (text.Length == 0)
        {
            error = "ds:SignatureValue is empty.";
            return false;
        }

        try
        {
            octets = Convert.FromBase64String(text);
            error = null;
            return true;
        }
        catch (FormatException)
        {
            error = "ds:SignatureValue is not valid Base64.";
            return false;
        }
    }

    /// <summary>
    /// Reads octets and throws <see cref="InvalidOperationException"/> on failure (missing / empty / invalid Base64).
    /// </summary>
    public static byte[] ReadOctetsOrThrow(XmlDocument document)
    {
        if (!TryReadOctets(document, out var octets, out var error))
        {
            throw new InvalidOperationException(error);
        }

        return octets;
    }

    /// <summary>Base64-encodes <paramref name="octets"/> into the first <c>ds:SignatureValue</c> element.</summary>
    /// <exception cref="InvalidOperationException"><c>ds:SignatureValue</c> element is missing.</exception>
    public static void WriteOctets(XmlDocument document, ReadOnlySpan<byte> octets)
    {
        ArgumentNullException.ThrowIfNull(document);
        if (!TryFindElement(document, out var el))
        {
            throw new InvalidOperationException("ds:SignatureValue element missing.");
        }

        el.InnerText = Convert.ToBase64String(octets);
    }

    /// <summary>Locates the first <c>ds:SignatureValue</c> element.</summary>
    private static bool TryFindElement(XmlDocument document, out XmlElement element)
    {
        var nodes = document.GetElementsByTagName("SignatureValue", SignedXml.XmlDsigNamespaceUrl);
        if (nodes.Count == 0 || nodes[0] is not XmlElement el)
        {
            element = null!;
            return false;
        }

        element = el;
        return true;
    }
}
