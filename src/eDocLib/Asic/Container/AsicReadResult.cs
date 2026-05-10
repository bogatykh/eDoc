using System.Collections.Generic;
using eDocLib;

namespace eDocLib.Asic.Container;

/// <summary>Outcome of <see cref="AsicContainerReader.Read"/>: ordered payloads and detached signatures parsed from ZIP.</summary>
internal class AsicReadResult
{
    /// <summary>Initializes a new ASiC read result instance.</summary>
    public AsicReadResult(IReadOnlyList<DataFile> dataFiles,
        IReadOnlyList<ISignature> signatures)
    {
        DataFiles = dataFiles;
        Signatures = signatures;
    }

    /// <summary>Payload files in manifest iteration order.</summary>
    public IReadOnlyList<DataFile> DataFiles { get; }

    /// <summary>Detached <see cref="ISignature"/> entries discovered under <c>META-INF</c>.</summary>
    public IReadOnlyList<ISignature> Signatures { get; }
}
