using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace eDocLib;

/// <summary>
/// Wraps an arbitrary XML signature document (e.g. tests or externally produced XAdES).
/// </summary>
internal sealed class RawXmlSignature : ISignature
{
    private readonly XmlDocument _document;

    /// <summary>Initializes a new raw XML signature instance.</summary>
    public RawXmlSignature(XmlDocument document)
    {
        _document = document ?? throw new ArgumentNullException(nameof(document));
    }

    public string Id => _document.DocumentElement?.GetAttribute("Id") ?? string.Empty;

    public string SignatureMethod
    {
        get
        {
            var nsm = XmlDsigXmlNamespaces.ForDs(_document.NameTable);
            var node = _document.SelectSingleNode("//ds:SignedInfo/ds:SignatureMethod", nsm);
            return node?.Attributes?["Algorithm"]?.Value ?? string.Empty;
        }
    }

    public X509Certificate? SigningCertificate => null;

    public IReadOnlyCollection<string> SignerRoles => [];

    public SignatureProductionPlace? SignatureProductionPlace => null;

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
}
