using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml.Linq;
using eDocLib;
using eDocLib.Asic.Container;
using eDocLib.Asic.Manifest;
using eDocLib.Configuration;
using eDocLib.Asic.Xades;
using ICSharpCode.SharpZipLib.Zip;
using Xunit;

namespace eDocLib.Tests;

/// <summary><see cref="Edoc.Open"/> error mapping and <see cref="Edoc.TryDetectContainer"/> edge cases.</summary>
public class EdocOpenAndProbeEdgeCaseTests
{
    [Fact]
    public void Open_null_stream_throws_ArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => Edoc.Open(EdocLibConfig.Default, (Stream)null!));
    }

    [Fact]
    public void Open_wraps_duplicate_mimetype_AsicException_as_EdocException_InvalidStructure()
    {
        var zip = BuildZipWithTrailingSecondMimetype(AsicContainer.MimeType, "application/vnd.etsi.asic-s+zip");

        var ex = Assert.Throws<EdocException>(() => Edoc.Open(EdocLibConfig.Default, new MemoryStream(zip)));
        Assert.Equal(EdocFailureKind.InvalidStructure, ex.Kind);
        Assert.Contains("Duplicate", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.IsAssignableFrom<AsicException>(ex.InnerException);
    }

    [Fact]
    public void Open_wraps_manifest_duplicate_full_path_ArgumentException_as_EdocException_InvalidFormat()
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

        var ex = Assert.Throws<EdocException>(() => Edoc.Open(EdocLibConfig.Default, new MemoryStream(zip)));
        Assert.Equal(EdocFailureKind.InvalidFormat, ex.Kind);
        Assert.IsAssignableFrom<ArgumentException>(ex.InnerException);
    }

    [Fact]
    public void TryDetectContainer_non_seekable_stream_throws_ArgumentException()
    {
        using var inner = new MemoryStream();
        using var wrapped = new NonSeekableStreamWrapper(inner);

        var ex = Assert.Throws<ArgumentException>(() => Edoc.TryDetectContainer(wrapped, out _));
        Assert.Contains("seekable", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Open_succeeds_when_local_zip_headers_start_after_a_small_prefix()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(
            "CN=pad",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(1));
        var payload = "pad"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2026-06-01T12:00:00Z"));

        using var inner = new MemoryStream();
        inner.Write(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }, 0, 4);
        using (var edoc = Edoc.CreateNew())
        {
            edoc.AddDataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain");
            edoc.AddSignature(sig);
            edoc.Save(inner);
        }

        inner.Position = 0;
        using var opened = Edoc.Open(EdocLibConfig.Default, inner);
        Assert.Single(opened.DataFiles);
        Assert.Equal("doc.txt", opened.DataFiles.First().Name);
    }

    [Fact]
    public void Open_non_zip_bytes_throws_EdocException_InvalidStructure()
    {
        using var ms = new MemoryStream(new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 });
        var ex = Assert.Throws<EdocException>(() => Edoc.Open(EdocLibConfig.Default, ms));
        Assert.Equal(EdocFailureKind.InvalidStructure, ex.Kind);
    }

    private static byte[] BuildZipWithTrailingSecondMimetype(string firstMimeBody, string secondMimeBody)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(
            "CN=dup-open",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(1));

        var payload = "trail-open"u8.ToArray();
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.Parse("2026-06-01T11:00:00Z"));
        var sigUtf8 = Encoding.UTF8.GetBytes(SerializeSig(sig));

        var manifest = new OasisManifest();
        manifest.Add("doc.txt", "text/plain");

        using var ms = new MemoryStream();
        using (var zos = new ZipOutputStream(ms) { IsStreamOwner = false })
        {
            void WriteMimeStored(byte[] body)
            {
                var e = new ZipEntry("mimetype") { CompressionMethod = CompressionMethod.Stored };
                zos.PutNextEntry(e);
                zos.Write(body, 0, body.Length);
                zos.CloseEntry();
            }

            WriteMimeStored(Encoding.UTF8.GetBytes(firstMimeBody));

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

            WriteMimeStored(Encoding.UTF8.GetBytes(secondMimeBody));
        }

        return ms.ToArray();
    }

    private static string SerializeSig(AsicSignature sig)
    {
        using var s = new MemoryStream();
        sig.WriteTo(s);
        return Encoding.UTF8.GetString(s.ToArray());
    }

    private sealed class NonSeekableStreamWrapper : Stream
    {
        private readonly MemoryStream _inner;

        public NonSeekableStreamWrapper(MemoryStream inner) => _inner = inner;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
