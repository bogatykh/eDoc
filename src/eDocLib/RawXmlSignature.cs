using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using eDocLib.Asic.Xades;

namespace eDocLib;

/// <summary>
/// Wraps an arbitrary XML signature document (e.g. tests or externally produced XAdES).
/// </summary>
internal sealed class RawXmlSignature : ISignature
{
    /// <summary>Stores the document.</summary>
    private readonly XmlDocument _document;

    /// <summary>Initializes a new raw XML signature instance.</summary>
    public RawXmlSignature(XmlDocument document)
    {
        _document = document ?? throw new ArgumentNullException(nameof(document));
    }

    /// <summary>Stores the ID.</summary>
    public string Id => _document.DocumentElement?.GetAttribute("Id") ?? string.Empty;

    public string SignatureMethod
    {
        get
        {
            var nsm = CreateDsNamespaceManager(_document);
            var node = _document.SelectSingleNode("//ds:SignedInfo/ds:SignatureMethod", nsm);
            return node?.Attributes?["Algorithm"]?.Value ?? string.Empty;
        }
    }

    /// <summary>Stores the signing certificate.</summary>
    public X509Certificate? SigningCertificate => null;

    /// <summary>Stores the signer roles.</summary>
    public IReadOnlyCollection<string> SignerRoles => [];

    /// <summary>Stores the signature production place.</summary>
    public SignatureProductionPlace? SignatureProductionPlace => null;

    /// <summary>Writes to.</summary>
    public void WriteTo(Stream stream)
    {
        var settings = new XmlWriterSettings
        {
            Encoding = new UTF8Encoding(false),
            Indent = false,
            OmitXmlDeclaration = false,
        };

        using var writer = XmlWriter.Create(stream, settings);
        _document.Save(writer);
    }

    /// <summary>Creates DSig namespace manager.</summary>
    private static XmlNamespaceManager CreateDsNamespaceManager(XmlDocument doc)
    {
        var nsm = new XmlNamespaceManager(doc.NameTable);
        nsm.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
        return nsm;
    }
}
