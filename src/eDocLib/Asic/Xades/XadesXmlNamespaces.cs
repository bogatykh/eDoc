using System.Xml;

namespace eDocLib.Asic.Xades;

/// <summary>Shared XPath namespace bindings for XAdES documents.</summary>
internal static class XadesXmlNamespaces
{
    /// <summary>Returns a namespace manager for XAdES elements.</summary>
    internal static XmlNamespaceManager ForXades(XmlNameTable nameTable)
    {
        var nsm = new XmlNamespaceManager(nameTable);
        nsm.AddNamespace(XadesSignature.XadesPrefix, XadesSignature.XadesNamespaceUrl);
        return nsm;
    }

    /// <summary>Returns a namespace manager for XAdES and XML-DSig elements.</summary>
    internal static XmlNamespaceManager ForXadesAndDs(XmlNameTable nameTable)
    {
        var nsm = ForXades(nameTable);
        nsm.AddNamespace("ds", System.Security.Cryptography.Xml.SignedXml.XmlDsigNamespaceUrl);
        return nsm;
    }
}
