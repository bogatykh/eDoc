using System.Security.Cryptography;
using System.Xml;
using eDocLib.Asic.Xades;

namespace eDocLib.Validation;

/// <summary>
/// Verifies RFC 3161 archive time-stamp message imprints against the default eDocLib archive digest input
/// (SHA-256 of UTF-8 <c>ds:Signature</c> XML after removing this and following <c>xades:ArchiveTimeStamp</c> blocks).
/// </summary>
internal static class ArchiveTimestampImprintVerifier
{
    /// <summary>
    /// Verifies every archive token in order against the reconstructed pre-append digest for that slot.
    /// </summary>
    public static bool TryVerifyAll(
        XmlDocument signatureOwnerDocument,
        IReadOnlyList<byte[]> archiveTokenDerInOrder,
        out string? error)
    {
        ArgumentNullException.ThrowIfNull(signatureOwnerDocument);
        ArgumentNullException.ThrowIfNull(archiveTokenDerInOrder);

        for (var i = 0; i < archiveTokenDerInOrder.Count; i++)
        {
            if (!TryVerifyAt(signatureOwnerDocument, i, archiveTokenDerInOrder.Count, archiveTokenDerInOrder[i], out error))
            {
                return false;
            }
        }

        error = null;
        return true;
    }

    /// <summary>Attempts to verify at.</summary>
    public static bool TryVerifyAt(
        XmlDocument signatureOwnerDocument,
        int index,
        int totalArchiveTokens,
        byte[] archiveTokenDer,
        out string? error)
    {
        ArgumentNullException.ThrowIfNull(signatureOwnerDocument);
        ArgumentNullException.ThrowIfNull(archiveTokenDer);
        error = null;

        if (index < 0 || index >= totalArchiveTokens)
        {
            error = "Archive time-stamp index is out of range.";
            return false;
        }

        var doc = (XmlDocument)signatureOwnerDocument.CloneNode(true);
        var elements = ListArchiveTimeStampElements(doc);
        if (elements.Count != totalArchiveTokens)
        {
            error =
                $"Archive time-stamp XML block count ({elements.Count}) does not match DER token count ({totalArchiveTokens}).";
            return false;
        }

        for (var j = index; j < elements.Count; j++)
        {
            elements[j].ParentNode!.RemoveChild(elements[j]);
        }

        var expected = XadesBesSigner.ComputeDefaultArchiveTimestampImprintSha256(doc);

        if (!SignatureTimestampVerifier.TryGetTimeStampMessageImprintSha256(archiveTokenDer, out var imprint, out error))
        {
            return false;
        }

        if (!CryptographicOperations.FixedTimeEquals(expected, imprint))
        {
            error =
                "Archive time-stamp message imprint does not match the default archive digest input (see ComputeDefaultArchiveTimestampImprintSha256).";
            return false;
        }

        return true;
    }

    /// <summary>Lists archive time stamp elements.</summary>
    private static List<XmlElement> ListArchiveTimeStampElements(XmlDocument doc)
    {
        var nsm = new XmlNamespaceManager(doc.NameTable);
        nsm.AddNamespace("xades", XadesSignature.XadesNamespaceUrl);
        var nodes = doc.SelectNodes("//xades:ArchiveTimeStamp", nsm);
        var list = new List<XmlElement>();
        if (nodes is null)
        {
            return list;
        }

        foreach (XmlNode n in nodes)
        {
            if (n is XmlElement el)
            {
                list.Add(el);
            }
        }

        return list;
    }
}
