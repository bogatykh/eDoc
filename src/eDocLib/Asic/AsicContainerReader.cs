using ICSharpCode.SharpZipLib.Zip;
using System;
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

        public AsicContainerReader(Stream stream)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            _zipInputStream = new ZipInputStream(stream);
            _zipInputStream.IsStreamOwner = false;
        }

        public void Read()
        {
            ReadEntries();
            Validate();
        }

        private void ReadEntries()
        {
            var zipEntry = _zipInputStream.GetNextEntry();

            while (zipEntry != null)
            {
                ReadEntry(zipEntry);

                zipEntry = _zipInputStream.GetNextEntry();
            }
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

        private bool IsMimeType(string fullName)
        {
            return string.Equals(fullName, AsicContainer.MimeTypeFileName, StringComparison.OrdinalIgnoreCase);
        }

        private bool IsManifest(string fullName)
        {
            return string.Equals(fullName, $"{AsicContainer.MetaFolderName}/{AsicContainer.ManifestFileName}", StringComparison.OrdinalIgnoreCase);
        }

        private void Validate()
        {
            if (!string.Equals(_mimeType, AsicContainer.MimeType, StringComparison.OrdinalIgnoreCase))
            {
                throw new Exception("Invalid format");
            }
        }

        public void Dispose()
        {
            _zipInputStream.Dispose();
        }
    }
}
