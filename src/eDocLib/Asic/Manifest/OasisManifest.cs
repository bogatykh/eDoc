using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Xml.Linq;
using eDocLib.Asic.Container;

namespace eDocLib.Asic.Manifest {
    /// <summary>
    /// OASIS OpenDocument manifest (<c>META-INF/manifest.xml</c>): maps ZIP entry paths to reported media types for ASiC-E.
    /// </summary>
    internal class OasisManifest
    {
        /// <summary>Defines the namespace name value.</summary>
        private const string NamespaceName = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0";
        /// <summary>Defines the namespace prefix value.</summary>
        private const string NamespacePrefix = "manifest";

        /// <summary>Defines the root full path value.</summary>
        private const string RootFullPath = "/";

        /// <summary>Defines the manifest element name value.</summary>
        private const string ManifestElementName = "manifest";
        /// <summary>Defines the file entry element name value.</summary>
        private const string FileEntryElementName = "file-entry";

        /// <summary>Defines the full path attribute name value.</summary>
        private const string FullPathAttributeName = "full-path";
        /// <summary>Defines the media type attribute name value.</summary>
        private const string MediaTypeAttributeName = "media-type";
        /// <summary>Defines the version attribute name value.</summary>
        private const string VersionAttributeName = "version";

        /// <summary>Defines the manifest version value.</summary>
        private const string ManifestVersion = "1.2";

        /// <summary>Stores the files.</summary>
        private readonly Dictionary<string, string> _files = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        /// <summary><c>full-path</c> → <c>media-type</c> from parsed manifest entries.</summary>
        public IReadOnlyDictionary<string, string> Files
        {
            get
            {
                return _files;
            }
        }

        /// <summary>Attempts to get media type.</summary>
        public bool TryGetMediaType(string fullPath, [NotNullWhen(true)] out string? mediaType) =>
            _files.TryGetValue(fullPath, out mediaType);

        /// <summary>Initializes a new oasis manifest instance.</summary>
        public OasisManifest()
        {
        }

        /// <summary>Parses an existing <c>manifest:manifest</c> root and indexes <c>file-entry</c> rows.</summary>
        public OasisManifest(XElement element)
        {
            foreach (var node in element.Elements(XName.Get(FileEntryElementName, NamespaceName)))
            {
                var fullPathAttribute = node.Attribute(XName.Get(FullPathAttributeName, NamespaceName));
                var mediaTypeAttribute = node.Attribute(XName.Get(MediaTypeAttributeName, NamespaceName));
                if (fullPathAttribute == null || mediaTypeAttribute == null)
                {
                    continue;
                }

                if (string.Equals(fullPathAttribute.Value, RootFullPath, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(mediaTypeAttribute.Value, AsicContainer.MimeType, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                _files.Add(fullPathAttribute.Value, mediaTypeAttribute.Value);
            }
        }

        /// <summary>Adds value.</summary>
        public void Add(string fullPath, string mediaType)
        {
            _files.Add(fullPath, mediaType);
        }

        /// <summary>Removes value.</summary>
        public void Remove(string fullPath)
        {
            _files.Remove(fullPath);
        }

        /// <summary>Generates the XML document.</summary>
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
