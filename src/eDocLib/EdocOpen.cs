using System.IO;
using eDocLib.Asic.Container;
using eDocLib.Configuration;
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
            throw new EdocException($"Failed to read file: {path}", EdocFailureKind.Io, ex);
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
            throw new EdocException("Failed to open EDOC package: " + ex.Message, EdocFailureKind.InvalidStructure, ex);
        }
        catch (ZipException ex)
        {
            throw new EdocException("Failed to open EDOC package: invalid ZIP container.", EdocFailureKind.InvalidStructure, ex);
        }
        catch (Exception ex) when (ex is IOException or ArgumentException or InvalidDataException or System.Xml.XmlException)
        {
            throw new EdocException("Failed to open EDOC package.", MapOpenFailure(ex), ex);
        }
    }

    private static EdocFailureKind MapOpenFailure(Exception ex) =>
        ex switch
        {
            IOException => EdocFailureKind.Io,
            InvalidDataException => EdocFailureKind.InvalidStructure,
            System.Xml.XmlException => EdocFailureKind.InvalidStructure,
            ArgumentException => EdocFailureKind.InvalidFormat,
            _ => EdocFailureKind.Unknown,
        };
}
