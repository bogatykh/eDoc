using System.Text;
using eDocLib.Asic.Container;
using ICSharpCode.SharpZipLib.Zip;
using Xunit;

namespace eDocLib.Tests;

/// <summary>Guard rails on <see cref="AsicContainerFormatProbe.TryDetectAsicE"/>.</summary>
public class AsicContainerFormatProbeGuardTests
{
    [Fact]
    public void TryDetectAsicE_non_seekable_stream_throws()
    {
        using var inner = new MemoryStream();
        using var wrapped = new NonSeekableStreamWrapper(inner);

        var ex = Assert.Throws<ArgumentException>(() => AsicContainerFormatProbe.TryDetectAsicE(wrapped, out _));
        Assert.Contains("seekable", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryDetectAsicE_max_entries_below_one_throws()
    {
        using var ms = BuildMinimalValidProbeZip();
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() =>
            AsicContainerFormatProbe.TryDetectAsicE(ms, maxZipEntriesToScan: 0, out _));
        Assert.Equal("maxZipEntriesToScan", ex.ParamName);
    }

    private static MemoryStream BuildMinimalValidProbeZip()
    {
        using var ms = new MemoryStream();
        using (var zos = new ZipOutputStream(ms) { IsStreamOwner = false })
        {
            var mt = new ZipEntry("mimetype")
            {
                CompressionMethod = CompressionMethod.Stored,
            };
            zos.PutNextEntry(mt);
            var mime = Encoding.UTF8.GetBytes(AsicContainer.MimeType);
            zos.Write(mime, 0, mime.Length);
            zos.CloseEntry();

            var man = new ZipEntry("META-INF/manifest.xml")
            {
                CompressionMethod = CompressionMethod.Deflated,
            };
            zos.PutNextEntry(man);
            var xml = Encoding.UTF8.GetBytes("<manifest xmlns=\"urn:oasis:names:tc:opendocument:xmlns:manifest:1.0\"/>");
            zos.Write(xml, 0, xml.Length);
            zos.CloseEntry();
        }

        return new MemoryStream(ms.ToArray());
    }

    /// <summary>Delegates read to an inner stream but hides seek capability (not used by SharpZipLib after ctor).</summary>
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
