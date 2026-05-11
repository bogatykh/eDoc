using System.Collections.Generic;
using System.IO;

namespace eDocLib.Validation;

/// <summary>
/// Adapter that exposes an <see cref="Edoc"/>'s data files as an <see cref="IValidationPayloadSource"/> without
/// materializing the entire payload set in memory.
/// </summary>
/// <remarks>
/// <para>
/// Each <see cref="TryOpen"/> rewinds the underlying <see cref="IDataFile.Stream"/> (when seekable) and returns it
/// directly so the verifier hashes from the existing stream instead of copying every file into a separate
/// <c>byte[]</c> dictionary keyed by reference URI. This is the central memory win behind streamed validation
/// for large ASiC-E payloads (<see cref="DetachedSignatureVerifier"/> handles the bounded-buffer path when XML
/// transforms force in-memory materialization).
/// </para>
/// <para>
/// Lookup is case-insensitive on the relative URI to match the legacy dictionary semantics in
/// <see cref="EdocValidation"/>. Stream ownership remains with the <see cref="Edoc"/>; the verifier does not
/// dispose the returned stream.
/// </para>
/// </remarks>
internal sealed class EdocDataFilePayloadSource : IValidationPayloadSource
{
    private readonly Dictionary<string, IDataFile> _byName;

    public EdocDataFilePayloadSource(Edoc edoc)
    {
        ArgumentNullException.ThrowIfNull(edoc);
        _byName = new Dictionary<string, IDataFile>(StringComparer.OrdinalIgnoreCase);
        foreach (var df in edoc.DataFiles)
        {
            _byName[df.Name] = df;
        }
    }

    public bool TryOpen(string relativeUri, out Stream stream)
    {
        if (_byName.TryGetValue(relativeUri, out var df))
        {
            if (df.Stream.CanSeek)
            {
                df.Stream.Position = 0;
            }

            stream = df.Stream;
            return true;
        }

        stream = Stream.Null;
        return false;
    }
}
