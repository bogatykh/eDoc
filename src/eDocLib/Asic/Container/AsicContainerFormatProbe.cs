using System.IO;
using System.Text;
using ICSharpCode.SharpZipLib.Zip;

namespace eDocLib.Asic.Container;

/// <summary>
/// Lightweight detection of ASiC-E container layout (first ZIP entry <c>mimetype</c>, stored, expected media type)
/// without full manifest/signature parsing. Requires a <see cref="Stream.CanSeek"/> stream so the position can be restored.
/// </summary>
internal static class AsicContainerFormatProbe
{
    /// <summary>How many non-directory ZIP entries to scan after <c>mimetype</c> when looking for <c>META-INF/manifest.xml</c>.</summary>
    public const int DefaultMaxZipEntriesToScan = 96;

    /// <inheritdoc cref="TryDetectAsicE(System.IO.Stream,int,out AsicEProbeResult)"/>
    public static bool TryDetectAsicE(Stream stream, out AsicEProbeResult result) =>
        TryDetectAsicE(stream, DefaultMaxZipEntriesToScan, out result);

    /// <summary>
    /// Returns <c>true</c> when the stream looks like an ASiC-E container: first payload entry is stored <c>mimetype</c>
    /// with content <see cref="AsicContainer.MimeType"/>, and <c>META-INF/manifest.xml</c> appears among the first
    /// <paramref name="maxZipEntriesToScan"/> file entries (directory entries do not count toward the limit).
    /// The ZIP central directory must list exactly one <c>mimetype</c> file entry (rejects duplicate or missing catalog rows).
    /// </summary>
    public static bool TryDetectAsicE(Stream stream, int maxZipEntriesToScan, out AsicEProbeResult result)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanSeek)
        {
            throw new ArgumentException("Stream must be seekable so the read position can be restored.", nameof(stream));
        }

        if (maxZipEntriesToScan < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(maxZipEntriesToScan));
        }

        var start = stream.Position;
        try
        {
            using var zip = new ZipInputStream(stream) { IsStreamOwner = false };
            var entry = zip.GetNextEntry();
            while (entry != null && entry.IsDirectory)
            {
                entry = zip.GetNextEntry();
            }

            if (entry == null)
            {
                result = new AsicEProbeResult(false, false, false, "ZIP has no file entries.");
                return false;
            }

            if (!string.Equals(entry.Name, AsicContainer.MimeTypeFileName, StringComparison.OrdinalIgnoreCase))
            {
                result = new AsicEProbeResult(false, false, false,
                    $"First file entry must be \"{AsicContainer.MimeTypeFileName}\"; got \"{entry.Name}\".");
                return false;
            }

            if (entry.CompressionMethod != CompressionMethod.Stored)
            {
                result = new AsicEProbeResult(false, false, false, "mimetype entry must use ZIP storage (uncompressed).");
                return false;
            }

            using var ms = new MemoryStream();
            zip.CopyTo(ms);
            var readMime = Encoding.UTF8.GetString(ms.ToArray()).Trim();
            if (!string.Equals(readMime, AsicContainer.MimeType, StringComparison.OrdinalIgnoreCase))
            {
                result = new AsicEProbeResult(false, false, false, $"Unexpected mimetype content: \"{readMime}\".");
                return false;
            }

            var manifestPath = AsicContainer.ManifestZipEntryPath;
            var seen = 0;
            var manifestSeen = false;
            while (seen < maxZipEntriesToScan)
            {
                entry = zip.GetNextEntry();
                if (entry == null)
                {
                    break;
                }

                if (entry.IsDirectory)
                {
                    continue;
                }

                seen++;
                if (string.Equals(entry.Name, manifestPath, StringComparison.OrdinalIgnoreCase))
                {
                    manifestSeen = true;
                    break;
                }
            }

            if (!manifestSeen)
            {
                result = new AsicEProbeResult(false, true, false,
                    $"\"{manifestPath}\" not found within the first {maxZipEntriesToScan} file entries after mimetype.");
                return false;
            }

            stream.Position = start;
            int mimetypeCatalogCount;
            try
            {
                using var catalog = new ZipFile(stream, leaveOpen: true, StringCodec.Default);
                mimetypeCatalogCount = 0;
                foreach (ZipEntry e in catalog)
                {
                    if (e.IsDirectory)
                    {
                        continue;
                    }

                    if (string.Equals(e.Name, AsicContainer.MimeTypeFileName, StringComparison.OrdinalIgnoreCase))
                    {
                        mimetypeCatalogCount++;
                    }
                }
            }
            catch (ZipException ex)
            {
                result = new AsicEProbeResult(false, true, true, "ZIP central directory could not be read: " + ex.Message);
                return false;
            }

            if (mimetypeCatalogCount != 1)
            {
                result = new AsicEProbeResult(
                    false,
                    true,
                    true,
                    $"Expected exactly one \"{AsicContainer.MimeTypeFileName}\" entry; ZIP catalog reports {mimetypeCatalogCount}.");
                return false;
            }

            result = new AsicEProbeResult(true, true, true, null);
            return true;
        }
        finally
        {
            stream.Position = start;
        }
    }
}

/// <summary>Provides ASiC e probe result.</summary>
/// <inheritdoc cref="IAsicProbeResult"/>
internal readonly record struct AsicEProbeResult(
    bool IsLikelyAsicE,
    bool MimeTypeEntryValid,
    bool ManifestEntrySeen,
    string? RejectionReason) : IAsicProbeResult;
