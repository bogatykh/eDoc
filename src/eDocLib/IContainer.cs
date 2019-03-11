using System.Collections.Generic;
using System.IO;

namespace eDocLib
{
    public interface IContainer
    {
        IReadOnlyCollection<DataFile> DataFiles { get; }

        DataFile AddDataFile(Stream stream, string name, string mimeType);

        IReadOnlyCollection<ISignature> Signatures { get; }
    }
}
