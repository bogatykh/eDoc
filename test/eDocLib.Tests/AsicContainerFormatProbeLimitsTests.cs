using System.Text;
using eDocLib.Asic.Container;
using ICSharpCode.SharpZipLib.Zip;
using Xunit;

namespace eDocLib.Tests;

/// <summary>
/// <see cref="AsicContainerFormatProbe.TryDetectAsicE(System.IO.Stream,int,out AsicEProbeResult)"/> —
/// manifest must appear within the first <paramref name="maxZipEntriesToScan"/> non-directory entries after <c>mimetype</c>.
/// </summary>
public class AsicContainerFormatProbeLimitsTests
{
    private const string MimeEntryName = "mimetype";
    private const string ManifestEntryPath = "META-INF/manifest.xml";

    [Fact]
    public void Manifest_after_many_entries_requires_large_enough_scan_limit()
    {
        const int junkBeforeManifest = 24;

        using var zipBytes = BuildZipMimetypeThenJunkThenManifest(junkBeforeManifest);
        zipBytes.Position = 0;

        Assert.False(
            AsicContainerFormatProbe.TryDetectAsicE(zipBytes, maxZipEntriesToScan: 10, out var tooTight),
            tooTight.RejectionReason);
        Assert.False(tooTight.ManifestEntrySeen);
        Assert.True(tooTight.MimeTypeEntryValid);
        Assert.Contains("META-INF/manifest.xml", tooTight.RejectionReason ?? string.Empty, StringComparison.OrdinalIgnoreCase);

        zipBytes.Position = 0;
        Assert.True(
            AsicContainerFormatProbe.TryDetectAsicE(zipBytes, maxZipEntriesToScan: 30, out var ok),
            ok.RejectionReason);
        Assert.True(ok.ManifestEntrySeen);
        Assert.True(ok.IsLikelyAsicE);
    }

    private static MemoryStream BuildZipMimetypeThenJunkThenManifest(int junkCount)
    {
        using var ms = new MemoryStream();
        using (var zos = new ZipOutputStream(ms) { IsStreamOwner = false })
        {
            var mt = new ZipEntry(MimeEntryName)
            {
                CompressionMethod = CompressionMethod.Stored,
            };
            zos.PutNextEntry(mt);
            var mime = Encoding.UTF8.GetBytes(AsicContainer.MimeType);
            zos.Write(mime, 0, mime.Length);
            zos.CloseEntry();

            for (var i = 0; i < junkCount; i++)
            {
                var je = new ZipEntry($"junk/junk-{i:D4}.bin")
                {
                    CompressionMethod = CompressionMethod.Stored,
                };
                zos.PutNextEntry(je);
                zos.WriteByte(0);
                zos.CloseEntry();
            }

            var man = new ZipEntry(ManifestEntryPath)
            {
                CompressionMethod = CompressionMethod.Deflated,
            };
            zos.PutNextEntry(man);
            var xml = Encoding.UTF8.GetBytes(
                """<?xml version="1.0" encoding="UTF-8"?><manifest xmlns="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"/>""");
            zos.Write(xml, 0, xml.Length);
            zos.CloseEntry();
        }

        return new MemoryStream(ms.ToArray());
    }
}
