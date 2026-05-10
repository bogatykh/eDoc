using System.Text;
using System.Xml.Linq;
using eDocLib;
using eDocLib.Asic.Container;
using Xunit;

namespace eDocLib.Tests;

/// <summary>Structural manifest anomalies at ZIP + XML boundary.</summary>
public class AsicManifestPayloadValidationTests
{
    [Fact]
    public void Manifest_file_entry_with_empty_full_path_lists_missing_payload_on_load()
    {
        XNamespace ns = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0";
        var manifestDoc = new XDocument(
            new XDeclaration("1.0", "utf-8", "no"),
            new XElement(
                ns + "manifest",
                new XAttribute(XNamespace.Xmlns + "manifest", ns.NamespaceName),
                new XAttribute(ns + "version", "1.2"),
                new XElement(
                    ns + "file-entry",
                    new XAttribute(ns + "full-path", "/"),
                    new XAttribute(ns + "media-type", AsicContainer.MimeType)),
                new XElement(
                    ns + "file-entry",
                    new XAttribute(ns + "full-path", ""),
                    new XAttribute(ns + "media-type", "text/plain")),
                new XElement(
                    ns + "file-entry",
                    new XAttribute(ns + "full-path", "doc.txt"),
                    new XAttribute(ns + "media-type", "text/plain"))));

        using var ms = new MemoryStream();
        using (var zos = new ICSharpCode.SharpZipLib.Zip.ZipOutputStream(ms) { IsStreamOwner = false })
        {
            var mt = new ICSharpCode.SharpZipLib.Zip.ZipEntry("mimetype")
            {
                CompressionMethod = ICSharpCode.SharpZipLib.Zip.CompressionMethod.Stored,
            };
            zos.PutNextEntry(mt);
            var mime = Encoding.UTF8.GetBytes(AsicContainer.MimeType);
            zos.Write(mime, 0, mime.Length);
            zos.CloseEntry();

            var man = new ICSharpCode.SharpZipLib.Zip.ZipEntry("META-INF/manifest.xml")
            {
                CompressionMethod = ICSharpCode.SharpZipLib.Zip.CompressionMethod.Deflated,
            };
            zos.PutNextEntry(man);
            manifestDoc.Save(zos);
            zos.CloseEntry();

            var data = new ICSharpCode.SharpZipLib.Zip.ZipEntry("doc.txt")
            {
                CompressionMethod = ICSharpCode.SharpZipLib.Zip.CompressionMethod.Deflated,
            };
            zos.PutNextEntry(data);
            var bytes = "x"u8.ToArray();
            zos.Write(bytes, 0, bytes.Length);
            zos.CloseEntry();
        }

        ms.Position = 0;
        var ex = Assert.Throws<AsicException>(() => new Edoc(ms));
        Assert.Contains("lists", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}
