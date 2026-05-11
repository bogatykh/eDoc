using ICSharpCode.SharpZipLib.Zip;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using eDocLib;
using eDocLib.Asic.Manifest;

namespace eDocLib.Asic.Container {
    /// <summary>
    /// Writes ASiC-E ZIP layout: stored <c>mimetype</c>, OASIS manifest, detached signatures, then payload streams.
    /// </summary>
    internal class AsicContainerWriter : IDisposable
    {
        private readonly ZipOutputStream _zipOutputStream;

        /// <summary>Initializes a new ASiC container writer instance.</summary>
        public AsicContainerWriter(Stream stream)
        {
            ArgumentNullException.ThrowIfNull(stream);

            _zipOutputStream = new ZipOutputStream(stream);
            _zipOutputStream.IsStreamOwner = false;
        }

        /// <summary>Writes mime type.</summary>
        public void WriteMimeType()
        {
            var entry = new ZipEntry(AsicContainer.MimeTypeFileName);
            entry.CompressionMethod = CompressionMethod.Stored;

            _zipOutputStream.PutNextEntry(entry);

            byte[] mimeType = Encoding.UTF8.GetBytes(AsicContainer.MimeType);
            _zipOutputStream.Write(mimeType, 0, mimeType.Length);

            _zipOutputStream.CloseEntry();
        }

        /// <summary>Writes manifest.</summary>
        public void WriteManifest(IEnumerable<IDataFile> dataFiles)
        {
            var manifest = new OasisManifest();

            foreach (var dataFile in dataFiles)
            {
                manifest.Add(dataFile.Name, dataFile.MimeType);
            }

            var entry = new ZipEntry(AsicContainer.ManifestZipEntryPath);

            _zipOutputStream.PutNextEntry(entry);

            manifest
                .Generate()
                .Save(_zipOutputStream);

            _zipOutputStream.CloseEntry();
        }

        /// <summary>Writes data files.</summary>
        public void WriteDataFiles(IEnumerable<IDataFile> dataFiles)
        {
            foreach (var dataFile in dataFiles)
            {
                var entry = new ZipEntry(dataFile.Name);

                _zipOutputStream.PutNextEntry(entry);

                dataFile.Stream.CopyTo(_zipOutputStream);

                _zipOutputStream.CloseEntry();
            }
        }

        /// <summary>Writes signatures.</summary>
        public void WriteSignatures(IEnumerable<ISignature> signatures)
        {
            int index = 0;

            foreach (var signature in signatures)
            {
                var entry = new ZipEntry(AsicContainer.MetaInfSlash + CreateSignatureFileName(signature, index));

                _zipOutputStream.PutNextEntry(entry);

                signature.WriteTo(_zipOutputStream);

                _zipOutputStream.CloseEntry();

                index++;
            }
        }

        /// <summary>Creates signature file name.</summary>
        protected virtual string CreateSignatureFileName(ISignature signature, int index)
        {
            return $"signatures{index}.xml";
        }

        /// <summary>Releases owned resources.</summary>
        public void Dispose()
        {
            _zipOutputStream.Dispose();
        }
    }
}
