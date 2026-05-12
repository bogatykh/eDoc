using System.IO;

namespace eDocLib.Container;

/// <summary>One payload entry in an ASiC-E package (logical file inside the ZIP).</summary>
public interface IDataFile
{
    /// <summary>Open payload bytes (memory- or disk-backed depending on size).</summary>
    Stream Stream { get; }

    /// <summary>ZIP entry path / logical name.</summary>
    string Name { get; }

    /// <summary>Declared media type (may be reconciled from <c>META-INF/manifest.xml</c> after load).</summary>
    string MimeType { get; }
}
