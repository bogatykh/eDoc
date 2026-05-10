using System.Xml;
using System.Xml.Linq;

namespace eDocLib.Validation;

/// <summary>Loads a TSL, optionally verifies its XML signature, and builds a <see cref="TrustedListServiceIndex"/>.</summary>
internal static class TrustedListReader
{
    /// <summary>
    /// Copies <paramref name="tslXml"/> to memory, loads with preserved whitespace, verifies XML-DSig when requested,
    /// then builds the service index from a LINQ XML view (semantically equivalent for <c>ServiceInformation</c> nodes).
    /// </summary>
    public static bool TryLoad(Stream tslXml, bool verifyXmlSignature, out TrustedListServiceIndex? index, out string? error) =>
        TryLoad(tslXml, verifyXmlSignature, out index, out _, out error);

    /// <summary>
    /// Same as <see cref="TryLoad(Stream, bool, out TrustedListServiceIndex?, out TrustedListDocumentMetadata?, out string?)"/>
    /// with a single <see cref="TrustedListLoadResult"/> (EP-40 convenience).
    /// </summary>
    public static bool TryLoadDocument(
        Stream tslXml,
        bool verifyXmlSignature,
        out TrustedListLoadResult? result,
        out string? error)
    {
        result = null;
        if (!TryLoad(tslXml, verifyXmlSignature, out var index, out var documentMetadata, out error) || index is null || documentMetadata is null)
        {
            return false;
        }

        result = new TrustedListLoadResult(index, documentMetadata);
        return true;
    }

    /// <summary>
    /// Same as <see cref="TryLoad(Stream, bool, out TrustedListServiceIndex?, out string?)"/> and also returns
    /// <see cref="TrustedListDocumentMetadata"/> from <c>SchemeInformation</c> when present.
    /// </summary>
    public static bool TryLoad(
        Stream tslXml,
        bool verifyXmlSignature,
        out TrustedListServiceIndex? index,
        out TrustedListDocumentMetadata? documentMetadata,
        out string? error)
    {
        ArgumentNullException.ThrowIfNull(tslXml);
        index = null;
        documentMetadata = null;
        error = null;

        using var ms = new MemoryStream();
        tslXml.CopyTo(ms);
        var buffer = ms.ToArray();

        var xmlDoc = new XmlDocument { PreserveWhitespace = true };
        using (var readMs = new MemoryStream(buffer, writable: false))
            xmlDoc.Load(readMs);

        if (verifyXmlSignature && !TrustedListXmlSignatureVerifier.TryVerify(xmlDoc, out error))
            return false;

        try
        {
            using var xread = new MemoryStream(buffer, writable: false);
            var xdoc = XDocument.Load(xread, LoadOptions.PreserveWhitespace);
            documentMetadata = TrustedListDocumentMetadata.FromXDocument(xdoc);
            index = TrustedListServiceIndex.FromXDocument(xdoc);
        }
        catch (Exception ex)
        {
            error = "Failed to parse TSL for service index: " + ex.Message;
            return false;
        }

        error = null;
        return true;
    }
}
