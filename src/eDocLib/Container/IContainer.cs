using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;

namespace eDocLib.Container;

/// <summary>ASiC-E style container surface: payload files and detached XML signatures.</summary>
public interface IContainer
{
    /// <summary>Files stored as ZIP payload entries.</summary>
    IReadOnlyCollection<IDataFile> DataFiles { get; }

    /// <summary>Adds a payload stream under the given logical name and MIME type.</summary>
    IDataFile AddDataFile(Stream stream, string name, string mimeType);

    /// <summary>Detached signatures serialized under <c>META-INF</c> when the container is saved.</summary>
    IReadOnlyCollection<ISignature> Signatures { get; }

    /// <summary>Adds a detached XAdES/XML-DSig signature file (written under META-INF on save).</summary>
    void AddSignature(ISignature signature);

    /// <summary>Resolves a detached signature by XML <c>ds:Signature</c> <c>Id</c> (or empty id if absent).</summary>
    bool TryResolveSignature(string signatureId, [NotNullWhen(true)] out ISignature? signature);
}
