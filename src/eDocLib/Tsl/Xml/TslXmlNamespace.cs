using System.Xml.Linq;

namespace eDocLib.Tsl.Xml;

/// <summary>
/// ETSI TS 119 612 XML namespace for <c>TrustServiceStatusList</c>.
/// </summary>
/// <remarks>
/// Shared low-level primitive consumed by both <c>eDocLib.Trust.Tsl</c> orchestration (fetch/manage TSL XML)
/// and <c>eDocLib.Validation</c> parsing/qualification. Lives outside both so neither module needs to depend
/// on the other for namespace constants.
/// </remarks>
internal static class TslXmlNamespace
{
    /// <summary>XML namespace literal: <c>http://uri.etsi.org/02231/v2#</c>.</summary>
    public const string NamespaceUri = "http://uri.etsi.org/02231/v2#";

    /// <summary>Reusable <see cref="XNamespace"/> for LINQ-to-XML queries.</summary>
    public static readonly XNamespace Tsl = NamespaceUri;
}
