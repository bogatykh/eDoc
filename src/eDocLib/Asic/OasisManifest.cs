using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml.Linq;

namespace eDocLib.Asic
{
    /// <summary>
    /// OASIS manifest
    /// </summary>
    public class OasisManifest
    {
        private const string NamespaceName = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0";
        private const string NamespacePrefix = "manifest";

        private const string RootFullPath = "/";

        private const string ManifestElementName = "manifest";
        private const string FileEntryElementName = "file-entry";

        private const string FullPathAttributeName = "full-path";
        private const string MediaTypeAttributeName = "media-type";
        private const string VersionAttributeName = "version";

        private const string ManifestVersion = "1.2";

        private readonly Dictionary<string, string> _files = new Dictionary<string, string>();

        public IReadOnlyDictionary<string, string> Files
        {
            get
            {
                return _files;
            }
        }

        public OasisManifest()
        {
        }

        public OasisManifest(XElement element)
        {
            foreach (var node in element.Elements(XName.Get(FileEntryElementName, NamespaceName)))
            {
                var fullPathAttribute = node.Attribute(XName.Get(FullPathAttributeName, NamespaceName));
                var mediaTypeAttribute = node.Attribute(XName.Get(MediaTypeAttributeName, NamespaceName));

                if (string.Equals(fullPathAttribute.Value, RootFullPath, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(mediaTypeAttribute.Value, AsicContainer.MimeType, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                _files.Add(fullPathAttribute.Value, mediaTypeAttribute.Value);
            }
        }

        public void Add(string fullPath, string mediaType)
        {
            _files.Add(fullPath, mediaType);
        }

        public void Remove(string fullPath)
        {
            _files.Remove(fullPath);
        }

        public XDocument Generate()
        {
            XNamespace ns = NamespaceName;

            var root = new XElement(ns + ManifestElementName,
                new XAttribute(XNamespace.Xmlns + NamespacePrefix, NamespaceName),
                new XAttribute(ns + VersionAttributeName, ManifestVersion),
                new XElement(ns + FileEntryElementName,
                    new XAttribute(ns + FullPathAttributeName, RootFullPath),
                    new XAttribute(ns + MediaTypeAttributeName, AsicContainer.MimeType)
                ),
                _files.Select(file =>
                    new XElement(ns + FileEntryElementName,
                        new XAttribute(ns + FullPathAttributeName, file.Key),
                        new XAttribute(ns + MediaTypeAttributeName, file.Value)
                    )
                )
            );

            return new XDocument(new XDeclaration("1.0", "utf-8", "no"),
                root);
        }
    }
}
