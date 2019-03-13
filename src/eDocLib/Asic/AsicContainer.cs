using System.Collections.Generic;
using System.IO;

namespace eDocLib.Asic
{
    /// <summary>
    /// ASiC-E container
    /// </summary>
    public abstract class AsicContainer : IContainer
    {
        public const string MimeType = "application/vnd.etsi.asic-e+zip";

        internal const string MimeTypeFileName = "mimetype";
        internal const string MetaFolderName = "META-INF";
        internal const string ManifestFileName = "manifest.xml";

        private readonly List<DataFile> _dataFiles = new List<DataFile>();
        private readonly List<AsicSignature> _signatures = new List<AsicSignature>();

        protected AsicContainer()
        {
        }

        protected AsicContainer(Stream stream)
        {
            Load(stream);
        }

        public IReadOnlyCollection<DataFile> DataFiles => _dataFiles.AsReadOnly();

        public IReadOnlyCollection<ISignature> Signatures => _signatures.AsReadOnly();

        public DataFile AddDataFile(Stream stream, string name, string mimeType)
        {
            var dataFile = new DataFile(stream, name, mimeType);

            AddDataFile(dataFile);

            return dataFile;
        }

        internal void AddDataFile(DataFile dataFile)
        {
            _dataFiles.Add(dataFile);
        }

        private void Load(Stream stream)
        {
            using (var reader = new AsicContainerReader(stream))
            {
                var result = reader.Read();

                _dataFiles.AddRange(result.DataFiles);
            }
        }

        public void Save(Stream stream)
        {
            using (var writer = new AsicContainerWriter(stream))
            {
                writer.WriteMimeType();
                writer.WriteManifest(_dataFiles);
                writer.WriteSignatures(_signatures);
                writer.WriteDataFiles(_dataFiles);
            }
        }
    }
}
