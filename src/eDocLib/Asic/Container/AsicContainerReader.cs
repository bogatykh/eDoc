using eDocLib;
using ICSharpCode.SharpZipLib.Zip;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using eDocLib.Asic.Manifest;

namespace eDocLib.Asic.Container {
    /// <summary>
    /// ASiC container reader. Validates MIME type, first ZIP entry (<c>mimetype</c>, stored; at most one such entry),
    /// manifest presence, each payload file listed in the manifest, and each non–META-INF manifest path
    /// (except <c>/</c> and <c>mimetype</c>) present as a payload entry.
    /// Payload files are exposed as <see cref="IDataFile.Stream"/>; depending on size and <see cref="AsicContainer.DefaultPayloadMemoryThresholdBytes"/>,
    /// that stream may be backed by memory or by a temporary file (see <see cref="ReadDataFile"/> spill behaviour).
    /// </summary>
    internal partial class AsicContainerReader : IDisposable
    {
        private readonly ZipInputStream _zipInputStream;
        private readonly long _payloadMemoryThresholdBytes;
        private readonly string? _payloadSpillTempDirectory;

        private static readonly Encoding Utf8Encoding = Encoding.UTF8;
        private static readonly Regex SignatureFileNameRegex = new Regex(
            $"{AsicContainer.MetaInfSlash}(.*)signatures(.*).xml",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        private string? _mimeType;
        private OasisManifest? _manifest;
        private readonly Dictionary<string, DataFile> _dataFiles = new Dictionary<string, DataFile>();
        private readonly List<DataFile> _dataFilesOrdered = new List<DataFile>();
        private readonly List<ISignature> _signatures = new List<ISignature>();
        private string? _firstNonDirectoryEntryName;
        private CompressionMethod? _firstNonDirectoryCompression;
        /// <summary>Whether a <c>mimetype</c> local file entry has already been consumed (ASiC-E allows at most one).</summary>
        private bool _mimetypeZipEntryConsumed;

        /// <summary>Initializes a new ASiC container reader instance.</summary>
        /// <param name="stream">Readable ZIP stream (typically positioned at the start of the ASiC package).</param>
        /// <param name="payloadMemoryThresholdBytes">Maximum uncompressed size to hold a payload entry in memory before spilling to disk.</param>
        /// <param name="payloadSpillTempDirectory">
        /// Optional directory for spill temp files; when <c>null</c>, files are created under <see cref="Path.GetTempPath"/>
        /// with unique names (no pre-created placeholder file).
        /// </param>
        public AsicContainerReader(
            Stream stream,
            long payloadMemoryThresholdBytes = AsicContainer.DefaultPayloadMemoryThresholdBytes,
            string? payloadSpillTempDirectory = null)
        {
            ArgumentNullException.ThrowIfNull(stream);

            if (payloadMemoryThresholdBytes < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(payloadMemoryThresholdBytes));
            }

            _payloadMemoryThresholdBytes = payloadMemoryThresholdBytes;
            _payloadSpillTempDirectory = PayloadSpillPathNormalize.FromOptionalDirectory(payloadSpillTempDirectory);
            _zipInputStream = new ZipInputStream(stream);
            _zipInputStream.IsStreamOwner = false;
        }

        /// <summary>Allocates a temporary spill-file path.</summary>
        private string AllocatePayloadSpillPath()
        {
            var dir = _payloadSpillTempDirectory ?? Path.GetTempPath();
            if (_payloadSpillTempDirectory is not null)
            {
                Directory.CreateDirectory(_payloadSpillTempDirectory);
            }

            return Path.Combine(dir, Guid.NewGuid().ToString("N") + ".tmp");
        }

        /// <summary>Reads the current input.</summary>
        public AsicReadResult Read()
        {
            ReadEntries();
            Validate();

            return new AsicReadResult(_dataFilesOrdered, _signatures);
        }

        /// <summary>Reads entries.</summary>
        private void ReadEntries()
        {
            var zipEntry = _zipInputStream.GetNextEntry();

            while (zipEntry != null)
            {
                if (!zipEntry.IsDirectory)
                {
                    _firstNonDirectoryEntryName ??= zipEntry.Name;
                    _firstNonDirectoryCompression ??= zipEntry.CompressionMethod;
                }

                ReadEntry(zipEntry);

                zipEntry = _zipInputStream.GetNextEntry();
            }

            UpdateDataFileMimeTypes();
        }

        /// <summary>Reads entry.</summary>
        protected virtual void ReadEntry(ZipEntry entry)
        {
            ArgumentNullException.ThrowIfNull(entry);

            if (IsMimeType(entry.Name))
            {
                ReadMimeType(entry);
            }
            else if (IsManifest(entry.Name))
            {
                ReadManifest(entry);
            }
            else if (IsDataFile(entry.Name))
            {
                ReadDataFile(entry);
            }
            else if (IsSignature(entry.Name))
            {
                ReadSignature(entry);
            }
        }

        /// <summary>Reads mime type.</summary>
        private void ReadMimeType(ZipEntry entry)
        {
            if (_mimetypeZipEntryConsumed)
            {
                throw new AsicException($"Duplicate ZIP entry \"{AsicContainer.MimeTypeFileName}\".");
            }

            using var ms = new MemoryStream();
            _zipInputStream.CopyTo(ms);
            var raw = ms.TryGetBuffer(out var seg)
                ? Utf8Encoding.GetString(seg.AsSpan())
                : Utf8Encoding.GetString(ms.ToArray());
            _mimeType = raw.TrimStart('\uFEFF').Trim();
            _mimetypeZipEntryConsumed = true;
        }

        /// <summary>Reads manifest.</summary>
        private void ReadManifest(ZipEntry entry)
        {
            _manifest = new OasisManifest(XElement.Load(_zipInputStream));
        }

        /// <summary>Reads data file.</summary>
        private void ReadDataFile(ZipEntry entry)
        {
            var uncompressedSize = entry.Size;
            var spill =
                uncompressedSize < 0
                || uncompressedSize > _payloadMemoryThresholdBytes;

            Stream payloadStream;
            if (!spill)
            {
                MemoryStream ms;
                if (uncompressedSize <= int.MaxValue)
                {
                    ms = new MemoryStream(checked((int)uncompressedSize));
                }
                else
                {
                    ms = new MemoryStream();
                }

                _zipInputStream.CopyTo(ms);
                ms.Position = 0;
                payloadStream = ms;
            }
            else
            {
                var tmp = AllocatePayloadSpillPath();
                try
                {
                    using (var outFs = new FileStream(
                               tmp,
                               FileMode.Create,
                               FileAccess.Write,
                               FileShare.None,
                               bufferSize: 65536,
                               options: FileOptions.SequentialScan))
                    {
                        _zipInputStream.CopyTo(outFs);
                    }

                    payloadStream = new FileStream(
                        tmp,
                        FileMode.Open,
                        FileAccess.Read,
                        FileShare.Read,
                        bufferSize: 4096,
                        options: FileOptions.DeleteOnClose);
                }
                catch
                {
                    // Best-effort temp cleanup before rethrow; DeleteOnClose only triggers if Open succeeded.
                    IoSafe.TryDeleteFile(tmp);
                    throw;
                }
            }

            var dataFile = new DataFile(
                stream: payloadStream,
                name: entry.Name,
                mimeType: System.Net.Mime.MediaTypeNames.Application.Octet,
                disposeStreamWithContainer: true);
            if (!_dataFiles.TryAdd(entry.Name, dataFile))
            {
                AsicStreamDispose.TryDispose(payloadStream);
                throw new AsicException($"Duplicate data file: {entry.Name}");
            }

            _dataFilesOrdered.Add(dataFile);
        }

        /// <summary>Reads signature.</summary>
        private void ReadSignature(ZipEntry entry)
        {
            var document = new XmlDocument();
            document.Load(_zipInputStream);

            _signatures.Add(new AsicSignature(document));
        }

        /// <summary>Updates data file mime types.</summary>
        private void UpdateDataFileMimeTypes()
        {
            if (_manifest == null)
            {
                return;
            }

            foreach (var dataFile in _dataFiles.Values)
            {
                if (_manifest.TryGetMediaType(dataFile.Name, out var mediaType))
                {
                    dataFile.MimeType = mediaType;
                }
            }
        }

        /// <summary>Returns whether mime type.</summary>
        private bool IsMimeType(string fullName)
        {
            return string.Equals(fullName, AsicContainer.MimeTypeFileName, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>Returns whether manifest.</summary>
        private bool IsManifest(string fullName)
        {
            return string.Equals(fullName, AsicContainer.ManifestZipEntryPath, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>Returns whether data file.</summary>
        private bool IsDataFile(string fullName)
        {
            return !fullName.StartsWith(AsicContainer.MetaInfSlash, StringComparison.OrdinalIgnoreCase) && !IsMimeType(fullName);
        }

        /// <summary>Returns whether signature.</summary>
        private bool IsSignature(string fullName)
        {
            return SignatureFileNameRegex.IsMatch(fullName);
        }

        /// <summary>Releases owned resources.</summary>
        public void Dispose()
        {
            _zipInputStream.Dispose();
        }
    }
}
