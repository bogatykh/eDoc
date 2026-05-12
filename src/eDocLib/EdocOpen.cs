using System.IO;
using eDocLib.Asic.Container;
using eDocLib.Configuration;
using eDocLib.Exceptions;
using ICSharpCode.SharpZipLib.Zip;

namespace eDocLib;

/// <summary>Single internal path for opening streams/paths with consistent <see cref="EdocException"/> mapping.</summary>
internal static class EdocOpen
{
    internal static Edoc OpenMapped(Stream stream, EdocLibConfig readConfig)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(readConfig);
        return OpenFromLoadedStream(stream, readConfig);
    }

    internal static Edoc OpenMapped(string path, EdocLibConfig readConfig)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        ArgumentNullException.ThrowIfNull(readConfig);
        try
        {
            using var fs = File.OpenRead(path);
            return OpenFromLoadedStream(fs, readConfig);
        }
        catch (EdocException)
        {
            throw;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new EdocIOException($"Failed to read file: {path}", ex);
        }
    }

    private static Edoc OpenFromLoadedStream(Stream stream, EdocLibConfig readConfig)
    {
        try
        {
            return new Edoc(stream, formatVersion: null, readConfig);
        }
        catch (ArgumentOutOfRangeException)
        {
            throw;
        }
        catch (AsicException ex)
        {
            throw new EdocInvalidStructureException("Failed to open EDOC package: " + ex.Message, ex);
        }
        catch (ZipException ex)
        {
            throw new EdocInvalidStructureException("Failed to open EDOC package: invalid ZIP container.", ex);
        }
        catch (Exception ex) when (ex is IOException or ArgumentException or InvalidDataException or System.Xml.XmlException)
        {
            throw MapOpenFailure(ex);
        }
    }

    private static EdocException MapOpenFailure(Exception ex) =>
        ex switch
        {
            IOException io => new EdocIOException("Failed to open EDOC package.", io),
            InvalidDataException id => new EdocInvalidStructureException("Failed to open EDOC package.", id),
            System.Xml.XmlException xml => new EdocInvalidStructureException("Failed to open EDOC package.", xml),
            ArgumentException arg => new EdocInvalidFormatException("Failed to open EDOC package.", arg),
            _ => new EdocUnknownException("Failed to open EDOC package.", ex),
        };
}
