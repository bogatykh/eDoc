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

        private readonly List<DataFile> _dataFiles = new List<DataFile>();

        protected AsicContainer()
        {
        }

        public IReadOnlyCollection<DataFile> DataFiles => _dataFiles.AsReadOnly();

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

        public void Save(Stream stream)
        {
            using (var writer = new AsicContainerWriter(stream))
            {
                writer.WriteMimeType();
                writer.WriteManifest(_dataFiles);
                writer.WriteDataFiles(_dataFiles);
            }
        }
    }
}
