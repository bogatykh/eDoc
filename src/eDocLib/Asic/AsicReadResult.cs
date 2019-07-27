using System.Collections.Generic;

namespace eDocLib.Asic
{
    public class AsicReadResult
    {
        public AsicReadResult(IReadOnlyCollection<DataFile> dataFiles,
            IReadOnlyCollection<AsicSignature> signatures)
        {
            DataFiles = dataFiles;
            Signatures = signatures;
        }

        public IReadOnlyCollection<DataFile> DataFiles { get; }

        public IReadOnlyCollection<AsicSignature> Signatures { get; }
    }
}
