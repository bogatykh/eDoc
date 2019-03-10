using ICSharpCode.SharpZipLib.Zip;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace eDocLib.Asic
{
    /// <summary>
    /// ASiC container writer
    /// </summary>
    public class AsicContainerWriter : IDisposable
    {
        private readonly ZipOutputStream _zipOutputStream;

        private const string MimeTypeFileName = "mimetype";
        private const string MetaFolderName = "META-INF";
        private const string ManifestFileName = "manifest.xml";

        private readonly static Encoding Encoding = Encoding.UTF8;

        public AsicContainerWriter(Stream stream)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            _zipOutputStream = new ZipOutputStream(stream);
            _zipOutputStream.IsStreamOwner = false;
        }

        public void WriteMimeType()
        {
            var entry = new ZipEntry(MimeTypeFileName);
            entry.CompressionMethod = CompressionMethod.Stored;

            _zipOutputStream.PutNextEntry(entry);

            byte[] mimeType = Encoding.UTF8.GetBytes(AsicContainer.MimeType);
            _zipOutputStream.Write(mimeType, 0, mimeType.Length);

            _zipOutputStream.CloseEntry();
        }

        public void WriteManifest(IEnumerable<DataFile> dataFiles)
        {
            var manifest = new OasisManifest();

            foreach (var dataFile in dataFiles)
            {
                manifest.Add(dataFile.Name, dataFile.MimeType);
            }

            var entry = new ZipEntry(Path.Combine(MetaFolderName, ManifestFileName));

            _zipOutputStream.PutNextEntry(entry);
            
                manifest
                    .Generate()
                    .Save(_zipOutputStream);

            _zipOutputStream.CloseEntry();
        }

        public void WriteDataFiles(IEnumerable<DataFile> dataFiles)
        {
            foreach (var dataFile in dataFiles)
            {
                var entry = new ZipEntry(dataFile.Name);

                _zipOutputStream.PutNextEntry(entry);

                dataFile.Stream.CopyTo(_zipOutputStream);

                _zipOutputStream.CloseEntry();
            }
        }

        public void Dispose()
        {
            _zipOutputStream.Dispose();
        }
    }
}
