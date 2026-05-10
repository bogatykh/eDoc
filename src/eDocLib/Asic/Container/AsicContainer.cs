using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using eDocLib;
using eDocLib.Configuration;

namespace eDocLib.Asic.Container {
    /// <summary>
    /// ASiC-E ZIP container: OASIS manifest, detached signatures under <c>META-INF</c>, and payload entries.
    /// </summary>
    internal sealed class AsicContainer : IContainer
    {
        /// <summary>MIME type written to the first ZIP entry (<c>mimetype</c>) for ASiC-E.</summary>
        public const string MimeType = "application/vnd.etsi.asic-e+zip";

        /// <summary>
        /// Default maximum uncompressed payload entry size to retain in a <see cref="MemoryStream"/> when reading (32 MiB).
        /// Larger or unknown-size entries may spill to a temporary file; see <see cref="EdocLibConfig.PayloadMemoryThresholdBytes"/> on the read profile passed to <see cref="Edoc"/>.
        /// </summary>
        public const long DefaultPayloadMemoryThresholdBytes = 32 * 1024 * 1024;

        /// <summary>Defines the mime type file name value.</summary>
        internal const string MimeTypeFileName = "mimetype";
        /// <summary>Defines the meta folder name value.</summary>
        internal const string MetaFolderName = "META-INF";
        /// <summary>Defines the manifest file name value.</summary>
        internal const string ManifestFileName = "manifest.xml";

        /// <summary>ZIP entry path <c>META-INF/manifest.xml</c> (ASiC-E).</summary>
        internal const string ManifestZipEntryPath = MetaFolderName + "/" + ManifestFileName;

        /// <summary>Defines the meta inf slash value.</summary>
        internal const string MetaInfSlash = MetaFolderName + "/";

        /// <summary>Stores the data files.</summary>
        private readonly List<DataFile> _dataFiles = new List<DataFile>();
        /// <summary>Stores the signatures.</summary>
        private readonly List<ISignature> _signatures = new List<ISignature>();
        /// <summary>Stores the signatures view.</summary>
        private ReadOnlyCollection<ISignature>? _signaturesView;

        /// <summary>Empty container for building a new package.</summary>
        internal AsicContainer()
        {
        }

        /// <summary>Loads from ZIP using read thresholds and optional spill directory.</summary>
        internal AsicContainer(Stream stream, long payloadMemoryThresholdBytes, string? payloadSpillTempDirectory = null)
        {
            Load(stream, payloadMemoryThresholdBytes, payloadSpillTempDirectory);
        }

        /// <summary>Stores the data files.</summary>
        /// <inheritdoc />
        public IReadOnlyCollection<IDataFile> DataFiles => _dataFiles;

        /// <summary>Stores the signatures.</summary>
        /// <inheritdoc />
        public IReadOnlyCollection<ISignature> Signatures => _signaturesView ??= _signatures.AsReadOnly();

        /// <summary>Payload file by index (same order as iteration in <see cref="DataFiles"/>).</summary>
        public IDataFile GetDataFileAt(int index)
        {
            if (index < 0 || index >= _dataFiles.Count)
            {
                throw new ArgumentOutOfRangeException(nameof(index));
            }

            return _dataFiles[index];
        }

        /// <summary>Detached signature by index (same order as iteration in <see cref="Signatures"/>).</summary>
        public ISignature GetSignatureAt(int index)
        {
            if (index < 0 || index >= _signatures.Count)
            {
                throw new ArgumentOutOfRangeException(nameof(index));
            }

            return _signatures[index];
        }

        /// <summary>Adds data file.</summary>
        /// <inheritdoc />
        public IDataFile AddDataFile(Stream stream, string name, string mimeType)
        {
            var dataFile = new DataFile(stream, name, mimeType);

            AddDataFile(dataFile);

            return dataFile;
        }

        /// <summary>Adds data file.</summary>
        internal void AddDataFile(DataFile dataFile)
        {
            _dataFiles.Add(dataFile);
        }

        /// <summary>Adds signature.</summary>
        /// <inheritdoc />
        public void AddSignature(ISignature signature)
        {
            ArgumentNullException.ThrowIfNull(signature);

            _signatures.Add(signature);
        }

        /// <summary>Removes a payload file by index.</summary>
        /// <exception cref="ArgumentOutOfRangeException">Index is outside the current list.</exception>
        public void RemoveDataFileAt(int index)
        {
            if (index < 0 || index >= _dataFiles.Count)
            {
                throw new ArgumentOutOfRangeException(nameof(index));
            }

            var df = _dataFiles[index];
            _dataFiles.RemoveAt(index);
            if (df.DisposeStreamWithContainer)
            {
                AsicStreamDispose.TryDispose(df.Stream);
            }
        }

        /// <summary>Releases payload streams.</summary>
        internal void DisposePayloadStreams()
        {
            foreach (var df in _dataFiles)
            {
                if (df.DisposeStreamWithContainer)
                {
                    AsicStreamDispose.TryDispose(df.Stream);
                }
            }

            _dataFiles.Clear();
        }

        /// <summary>Removes a signature file by index.</summary>
        /// <exception cref="ArgumentOutOfRangeException">Index is outside the current list.</exception>
        public void RemoveSignatureAt(int index)
        {
            if (index < 0 || index >= _signatures.Count)
            {
                throw new ArgumentOutOfRangeException(nameof(index));
            }

            _signatures.RemoveAt(index);
        }

        /// <summary>Removes the first signature whose <see cref="ISignature.Id"/> matches <paramref name="signatureId"/>.</summary>
        /// <returns><c>true</c> if a signature was removed.</returns>
        public bool RemoveSignature(string signatureId)
        {
            var index = IndexOfSignature(signatureId);
            if (index < 0)
            {
                return false;
            }

            _signatures.RemoveAt(index);
            return true;
        }

        /// <summary>Attempts to resolve a signature by ID.</summary>
        /// <inheritdoc />
        public bool TryResolveSignature(string signatureId, [NotNullWhen(true)] out ISignature? signature)
        {
            var index = IndexOfSignature(signatureId);
            if (index < 0)
            {
                signature = null;
                return false;
            }

            signature = _signatures[index];
            return true;
        }

        /// <summary>Returns the index of of signature.</summary>
        private int IndexOfSignature(string signatureId)
        {
            if (string.IsNullOrEmpty(signatureId))
            {
                return -1;
            }

            for (var i = 0; i < _signatures.Count; i++)
            {
                if (string.Equals(_signatures[i].Id, signatureId, StringComparison.Ordinal))
                {
                    return i;
                }
            }

            return -1;
        }

        /// <summary>Loads configured data.</summary>
        private void Load(Stream stream, long payloadMemoryThresholdBytes, string? payloadSpillTempDirectory)
        {
            using var reader = new AsicContainerReader(stream, payloadMemoryThresholdBytes, payloadSpillTempDirectory);
            var result = reader.Read();
            _dataFiles.AddRange(result.DataFiles);
            _signatures.AddRange(result.Signatures);
        }

        /// <summary>Sets each payload stream position to 0 when <see cref="Stream.CanSeek"/>.</summary>
        internal void ResetSeekablePayloadPositions()
        {
            foreach (var df in _dataFiles)
            {
                if (df.Stream.CanSeek)
                {
                    df.Stream.Position = 0;
                }
            }
        }

        /// <summary>Serializes <see cref="MimeType"/>, manifest, signatures, and payload streams into <paramref name="stream"/>.</summary>
        public void Save(Stream stream)
        {
            ResetSeekablePayloadPositions();

            using var writer = new AsicContainerWriter(stream);
            writer.WriteMimeType();
            writer.WriteManifest(_dataFiles);
            writer.WriteSignatures(_signatures);
            writer.WriteDataFiles(_dataFiles);
        }
    }
}
