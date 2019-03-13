using ICSharpCode.SharpZipLib.Zip;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml.Linq;

namespace eDocLib.Asic
{
    /// <summary>
    /// ASiC container reader
    /// </summary>
    public class AsicContainerReader : IDisposable
    {
        private readonly ZipInputStream _zipInputStream;

        private readonly static Encoding Encoding = Encoding.UTF8;

        private string _mimeType;
        private OasisManifest _manifest;
        private readonly Dictionary<string, DataFile> _dataFiles = new Dictionary<string, DataFile>();

        public AsicContainerReader(Stream stream)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            _zipInputStream = new ZipInputStream(stream);
            _zipInputStream.IsStreamOwner = false;
        }

        public AsicReadResult Read()
        {
            ReadEntries();
            Validate();

            return new AsicReadResult(_dataFiles.Values);
        }

        private void ReadEntries()
        {
            var zipEntry = _zipInputStream.GetNextEntry();

            while (zipEntry != null)
            {
                ReadEntry(zipEntry);

                zipEntry = _zipInputStream.GetNextEntry();
            }

            UpdateDataFileMimeTypes();
        }

        protected virtual void ReadEntry(ZipEntry entry)
        {
            if (entry == null)
            {
                throw new ArgumentNullException(nameof(entry));
            }

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
        }

        private void ReadMimeType(ZipEntry entry)
        {
            using (var ms = new MemoryStream())
            {
                _zipInputStream.CopyTo(ms);

                _mimeType = Encoding.GetString(ms.ToArray());
            }
        }

        private void ReadManifest(ZipEntry entry)
        {
            _manifest = new OasisManifest(XElement.Load(_zipInputStream));
        }

        private void ReadDataFile(ZipEntry entry)
        {
            if (_dataFiles.ContainsKey(entry.Name))
            {
                throw new AsicException($"Duplicate data file: {entry.Name}");
            }

            var ms = new MemoryStream();

            _zipInputStream.CopyTo(ms);
            ms.Seek(0, SeekOrigin.Begin);

            _dataFiles.Add(entry.Name, new DataFile(
                stream: ms,
                name: entry.Name,
                mimeType: System.Net.Mime.MediaTypeNames.Application.Octet
            ));
        }

        private void UpdateDataFileMimeTypes()
        {
            if (_manifest == null)
            {
                return;
            }

            foreach (var dataFile in _dataFiles.Values)
            {
                if (!_manifest.Files.ContainsKey(dataFile.Name))
                {
                    continue;
                }

                dataFile.MimeType = _manifest.Files[dataFile.Name];
            }
        }

        private bool IsMimeType(string fullName)
        {
            return string.Equals(fullName, AsicContainer.MimeTypeFileName, StringComparison.OrdinalIgnoreCase);
        }

        private bool IsManifest(string fullName)
        {
            return string.Equals(fullName, $"{AsicContainer.MetaFolderName}/{AsicContainer.ManifestFileName}", StringComparison.OrdinalIgnoreCase);
        }

        private bool IsDataFile(string fullName)
        {
            return !fullName.StartsWith($"{AsicContainer.MetaFolderName}/", StringComparison.OrdinalIgnoreCase) && !IsMimeType(fullName);
        }

        private void Validate()
        {
            if (!string.Equals(_mimeType, AsicContainer.MimeType, StringComparison.OrdinalIgnoreCase))
            {
                throw new AsicException($"Invalid MIME type: {_mimeType}");
            }
        }

        public void Dispose()
        {
            _zipInputStream.Dispose();
        }
    }
}
