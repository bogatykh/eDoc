using System.Xml;

namespace eDocLib.Asic.Xades;

/// <summary>
/// Shared XML-DSig / XAdES DOM settings and efficient cloning for signing pipelines.
/// Cloning uses <see cref="XmlDocument.ImportNode"/> instead of <c>LoadXml(OuterXml)</c> to avoid redundant serialize/parse cycles
/// while preserving the same logical tree for Exclusive C14N inputs.
/// </summary>
internal static class XadesXmlDocument
{
    /// <summary>Creates an empty XML document.</summary>
    internal static XmlDocument Empty() =>
        new XmlDocument { PreserveWhitespace = false };

    /// <summary>Deep-clones <paramref name="source"/> under a new document root.</summary>
    internal static XmlDocument Clone(XmlDocument source)
    {
        ArgumentNullException.ThrowIfNull(source);
        var root = source.DocumentElement ?? throw new ArgumentException("Document has no root element.", nameof(source));
        var copy = Empty();
        copy.AppendChild(copy.ImportNode(root, deep: true));
        return copy;
    }
}
