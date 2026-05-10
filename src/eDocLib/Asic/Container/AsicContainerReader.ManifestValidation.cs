using System.Linq;
using ICSharpCode.SharpZipLib.Zip;
using eDocLib.Asic.Manifest;

namespace eDocLib.Asic.Container {
    /// <summary>Partial class: validates MIME entry, manifest presence, and manifest vs ZIP entry consistency.</summary>
    internal partial class AsicContainerReader
    {
        /// <summary>Throws <see cref="AsicException"/> when ZIP layout or manifest does not match ASiC-E expectations.</summary>
        private void Validate()
        {
            if (_mimeType == null ||
                !string.Equals(_mimeType, AsicContainer.MimeType, StringComparison.OrdinalIgnoreCase))
            {
                throw new AsicException($"Invalid MIME type: {_mimeType ?? "(missing)"}");
            }

            if (_firstNonDirectoryEntryName == null ||
                !string.Equals(_firstNonDirectoryEntryName, AsicContainer.MimeTypeFileName, StringComparison.OrdinalIgnoreCase))
            {
                throw new AsicException(
                    $"First ZIP entry must be \"{AsicContainer.MimeTypeFileName}\" (stored); got \"{_firstNonDirectoryEntryName ?? "(none)"}\".");
            }

            if (_firstNonDirectoryCompression != CompressionMethod.Stored)
            {
                throw new AsicException("The mimetype entry must use ZIP storage (uncompressed).");
            }

            if (_manifest == null)
            {
                throw new AsicException($"Missing {AsicContainer.ManifestZipEntryPath}.");
            }

            foreach (var path in _dataFiles.Keys)
            {
                if (!ManifestListsPath(_manifest, path))
                {
                    throw new AsicException($"Data file \"{path}\" is not listed in META-INF/manifest.xml.");
                }
            }

            foreach (var manifestPath in _manifest.Files.Keys)
            {
                if (IsManifestRootOrMetaEntry(manifestPath))
                {
                    continue;
                }

                if (!DataFilesContainPath(manifestPath))
                {
                    throw new AsicException(
                        $"META-INF/manifest.xml lists \"{manifestPath}\" but that file is not present in the container.");
                }
            }
        }

        /// <summary>Returns whether a data file exists at the path.</summary>
        private bool DataFilesContainPath(string path) =>
            _dataFiles.Keys.Any(k => string.Equals(k, path, StringComparison.OrdinalIgnoreCase));

        /// <summary>Returns whether manifest root or meta entry.</summary>
        private static bool IsManifestRootOrMetaEntry(string manifestPath)
        {
            if (string.Equals(manifestPath, "/", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (manifestPath.StartsWith(AsicContainer.MetaInfSlash, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return string.Equals(manifestPath, AsicContainer.MimeTypeFileName, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>Returns whether the manifest lists the path.</summary>
        private static bool ManifestListsPath(OasisManifest manifest, string path) =>
            manifest.TryGetMediaType(path, out _);
    }
}
