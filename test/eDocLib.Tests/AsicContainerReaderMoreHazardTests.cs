using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using eDocLib;
using eDocLib.Asic.Container;
using eDocLib.Asic.Manifest;
using eDocLib.Validation;
using eDocLib.Asic.Xades;
using ICSharpCode.SharpZipLib.Zip;
using Xunit;

namespace eDocLib.Tests;

/// <summary>
/// Additional ASiC reader edge cases aimed at regression-hunting (ZIP order, manifest parsing, signature shell).
/// </summary>
public class AsicContainerReaderMoreHazardTests
{
    private static string SerializeSig(AsicSignature sig)
    {
        using var s = new MemoryStream();
        sig.WriteTo(s);
        return Encoding.UTF8.GetString(s.ToArray());
    }

    /// <summary>
    /// A second stored <c>mimetype</c> entry <em>after</em> manifest/signature/payload overwrites the parsed MIME string —
    /// distinct from two <c>mimetype</c> entries before the manifest (covered by committed invalid fixtures).
    /// </summary>
    [Fact]
    public async Task Trailing_second_mimetype_entry_with_non_e_body_rejected_on_validate()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=trail-mime", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "trail"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2026-05-12T10:00:00Z"));
        var sigUtf8 = Encoding.UTF8.GetBytes(SerializeSig(sig));

        var manifest = new OasisManifest();
        manifest.Add("doc.txt", "text/plain");

        using var ms = new MemoryStream();
        using (var zos = new ZipOutputStream(ms) { IsStreamOwner = false })
        {
            void WriteMimeStored(string name, byte[] body)
            {
                var e = new ZipEntry(name) { CompressionMethod = CompressionMethod.Stored };
                zos.PutNextEntry(e);
                zos.Write(body, 0, body.Length);
                zos.CloseEntry();
            }

            WriteMimeStored("mimetype", Encoding.UTF8.GetBytes(AsicContainer.MimeType));

            var man = new ZipEntry("META-INF/manifest.xml") { CompressionMethod = CompressionMethod.Deflated };
            zos.PutNextEntry(man);
            manifest.Generate().Save(zos);
            zos.CloseEntry();

            var se = new ZipEntry("META-INF/signatures0.xml") { CompressionMethod = CompressionMethod.Deflated };
            zos.PutNextEntry(se);
            zos.Write(sigUtf8, 0, sigUtf8.Length);
            zos.CloseEntry();

            var data = new ZipEntry("doc.txt") { CompressionMethod = CompressionMethod.Deflated };
            zos.PutNextEntry(data);
            zos.Write(payload, 0, payload.Length);
            zos.CloseEntry();

            WriteMimeStored("mimetype", Encoding.UTF8.GetBytes("application/vnd.etsi.asic-s+zip"));
        }

        ms.Position = 0;
        var ex = Assert.Throws<AsicException>(() => new Edoc(ms));
        Assert.Contains("Duplicate", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("mimetype", ex.Message, StringComparison.OrdinalIgnoreCase);

        ms.Position = 0;
        Assert.False(Edoc.TryDetectContainer(ms, out var probe));
        Assert.Contains("Expected exactly one", probe.RejectionReason ?? string.Empty, StringComparison.Ordinal);
        Assert.Contains("mimetype", probe.RejectionReason ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Manifest_xml_duplicate_full_path_same_spelling_throws_on_load()
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
                    new XAttribute(ns + "full-path", "doc.txt"),
                    new XAttribute(ns + "media-type", "text/plain")),
                new XElement(
                    ns + "file-entry",
                    new XAttribute(ns + "full-path", "doc.txt"),
                    new XAttribute(ns + "media-type", "text/plain"))));

        var utf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
        var manifestBytes = utf8.GetBytes(manifestDoc.ToString(SaveOptions.DisableFormatting));

        var zip = ZipTestHelpers.BuildMinimalAsicZipRawManifestUtf8(
            manifestBytes,
            new Dictionary<string, byte[]> { ["doc.txt"] = "x"u8.ToArray() },
            Array.Empty<byte[]>());

        Assert.Throws<ArgumentException>(() => new Edoc(new MemoryStream(zip)));
    }

    [Fact]
    public async Task Manifest_xml_duplicate_full_path_differing_only_by_case_throws_on_load()
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
                    new XAttribute(ns + "full-path", "DOC.TXT"),
                    new XAttribute(ns + "media-type", "text/plain")),
                new XElement(
                    ns + "file-entry",
                    new XAttribute(ns + "full-path", "doc.txt"),
                    new XAttribute(ns + "media-type", "application/octet-stream"))));

        var utf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
        var manifestBytes = utf8.GetBytes(manifestDoc.ToString(SaveOptions.DisableFormatting));

        var zip = ZipTestHelpers.BuildMinimalAsicZipRawManifestUtf8(
            manifestBytes,
            new Dictionary<string, byte[]> { ["doc.txt"] = "y"u8.ToArray() },
            Array.Empty<byte[]>());

        Assert.Throws<ArgumentException>(() => new Edoc(new MemoryStream(zip)));
    }

    /// <summary>
    /// <see cref="AsicContainerReader.ManifestValidation"/> skips manifest rows whose <c>full-path</c> is under <c>META-INF/</c>,
    /// so a listed path need not exist as a payload ZIP entry (documents current behaviour).
    /// </summary>
    [Fact]
    public async Task Manifest_lists_META_INF_path_without_zip_entry_does_not_fail_structural_validation()
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
                    new XAttribute(ns + "full-path", "META-INF/only-in-manifest.xml"),
                    new XAttribute(ns + "media-type", "text/xml")),
                new XElement(
                    ns + "file-entry",
                    new XAttribute(ns + "full-path", "payload.txt"),
                    new XAttribute(ns + "media-type", "text/plain"))));

        var utf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
        var manifestBytes = utf8.GetBytes(manifestDoc.ToString(SaveOptions.DisableFormatting));

        var zip = ZipTestHelpers.BuildMinimalAsicZipRawManifestUtf8(
            manifestBytes,
            new Dictionary<string, byte[]> { ["payload.txt"] = "ok"u8.ToArray() },
            Array.Empty<byte[]>());

        var edoc = new Edoc(new MemoryStream(zip));
        Assert.Single(edoc.DataFiles);
        Assert.Equal("payload.txt", edoc.DataFiles.First().Name);
    }

    [Fact]
    public async Task First_mimetype_zip_entry_name_mixed_case_still_opens_and_validates()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=mime-case", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var payload = "case"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2026-05-12T11:00:00Z"));
        var sigUtf8 = Encoding.UTF8.GetBytes(SerializeSig(sig));

        var manifest = new OasisManifest();
        manifest.Add("doc.txt", "text/plain");

        using var ms = new MemoryStream();
        using (var zos = new ZipOutputStream(ms) { IsStreamOwner = false })
        {
            var mt = new ZipEntry("MiMeTyPe") { CompressionMethod = CompressionMethod.Stored };
            zos.PutNextEntry(mt);
            var mime = Encoding.UTF8.GetBytes(AsicContainer.MimeType);
            zos.Write(mime, 0, mime.Length);
            zos.CloseEntry();

            var man = new ZipEntry("META-INF/manifest.xml") { CompressionMethod = CompressionMethod.Deflated };
            zos.PutNextEntry(man);
            manifest.Generate().Save(zos);
            zos.CloseEntry();

            var se = new ZipEntry("META-INF/signatures0.xml") { CompressionMethod = CompressionMethod.Deflated };
            zos.PutNextEntry(se);
            zos.Write(sigUtf8, 0, sigUtf8.Length);
            zos.CloseEntry();

            var data = new ZipEntry("doc.txt") { CompressionMethod = CompressionMethod.Deflated };
            zos.PutNextEntry(data);
            zos.Write(payload, 0, payload.Length);
            zos.CloseEntry();
        }

        ms.Position = 0;
        var report = await EdocValidation.OpenAndValidateAsync(ms, SignatureTrustPolicy.CryptographyOnly);
        Assert.True(report.AllSignaturesValid, report.Signatures.ElementAtOrDefault(0)?.Result.Error);
    }

    [Fact]
    public async Task Signature_entry_empty_stream_throws_on_load()
    {
        var manifest = new OasisManifest();
        manifest.Add("doc.txt", "text/plain");

        var zip = ZipTestHelpers.BuildMinimalAsicZip(
            manifest.Generate(),
            new Dictionary<string, byte[]> { ["doc.txt"] = "z"u8.ToArray() },
            new List<byte[]> { Array.Empty<byte>() });

        Assert.ThrowsAny<XmlException>(() => new Edoc(new MemoryStream(zip)));
    }

    [Fact]
    public async Task Signature_entry_well_formed_xml_without_ds_Signature_throws_ArgumentException()
    {
        var manifest = new OasisManifest();
        manifest.Add("doc.txt", "text/plain");
        var junk = Encoding.UTF8.GetBytes("<?xml version=\"1.0\" encoding=\"UTF-8\"?><container xmlns=\"urn:test\"><note>no signature</note></container>");

        var zip = ZipTestHelpers.BuildMinimalAsicZip(
            manifest.Generate(),
            new Dictionary<string, byte[]> { ["doc.txt"] = "z"u8.ToArray() },
            new List<byte[]> { junk });

        var ex = Assert.Throws<ArgumentException>(() => new Edoc(new MemoryStream(zip)));
        Assert.Contains("Signature", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}
