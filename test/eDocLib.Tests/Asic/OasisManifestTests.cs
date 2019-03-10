using System.Collections.Generic;
using System.Xml.Linq;
using Xunit;

namespace eDocLib.Asic
{
    public class OasisManifestTests
    {
        [Fact]
        public void LoadManifestTest()
        {
            var manifest = XElement.Parse(@"<?xml version=""1.0"" encoding=""UTF-8"" standalone=""no""?>
<manifest:manifest xmlns:manifest=""urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"" manifest:version=""1.2"">
<manifest:file-entry manifest:full-path=""/"" manifest:media-type=""application/vnd.etsi.asic-e+zip""/>
<manifest:file-entry manifest:full-path=""file.doc"" manifest:media-type=""application/msword""/>
<manifest:file-entry manifest:full-path=""file.docx"" manifest:media-type=""application/octet-stream""/>
<manifest:file-entry manifest:full-path=""file2.docx"" manifest:media-type=""application/octet-stream""/>
<manifest:file-entry manifest:full-path=""datne.pdf"" manifest:media-type=""application/pdf""/>
</manifest:manifest>");
            var target = new OasisManifest(manifest);

            Assert.Equal(new Dictionary<string, string>
            {
                { "file.doc", "application/msword" },
                { "file.docx", "application/octet-stream" },
                { "file2.docx", "application/octet-stream" },
                { "datne.pdf", "application/pdf" },
            }, target.Files);
        }

        [Fact]
        public void CreateManifestTest()
        {
            var target = new OasisManifest();
            target.Add("file.doc", "application/msword");
            target.Add("datne.pdf", "application/pdf");
            target.Add("file2.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document");

            var actual = target.Generate();

            Assert.Equal(@"<manifest:manifest xmlns:manifest=""urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"" manifest:version=""1.2"">" +
@"<manifest:file-entry manifest:full-path=""/"" manifest:media-type=""application/vnd.etsi.asic-e+zip"" />" +
@"<manifest:file-entry manifest:full-path=""file.doc"" manifest:media-type=""application/msword"" />" +
@"<manifest:file-entry manifest:full-path=""datne.pdf"" manifest:media-type=""application/pdf"" />" +
@"<manifest:file-entry manifest:full-path=""file2.docx"" manifest:media-type=""application/vnd.openxmlformats-officedocument.wordprocessingml.document"" />" +
@"</manifest:manifest>",
                actual.ToString(SaveOptions.DisableFormatting));
        }
    }
}
