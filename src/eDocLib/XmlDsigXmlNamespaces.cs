using System.Security.Cryptography.Xml;
using System.Xml;

namespace eDocLib;

/// <summary>Shared XPath namespace bindings for XML Digital Signature documents.</summary>
internal static class XmlDsigXmlNamespaces
{
    /// <summary>Returns a namespace manager binding the <c>ds</c> XML-DSig prefix.</summary>
    internal static XmlNamespaceManager ForDs(XmlNameTable nameTable)
    {
        var nsm = new XmlNamespaceManager(nameTable);
        nsm.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
        return nsm;
    }
}
