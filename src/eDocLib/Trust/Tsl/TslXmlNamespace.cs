using System.Xml.Linq;

namespace eDocLib.Trust.Tsl;

/// <summary>ETSI TS 119 612 XML namespace for <c>TrustServiceStatusList</c>.</summary>
internal static class TslXmlNamespace
{
    /// <summary>XML namespace literal: <c>http://uri.etsi.org/02231/v2#</c>.</summary>
    public const string NamespaceUri = "http://uri.etsi.org/02231/v2#";

    /// <summary>Reusable <see cref="XNamespace"/> for LINQ-to-XML queries.</summary>
    public static readonly XNamespace Tsl = NamespaceUri;
}
