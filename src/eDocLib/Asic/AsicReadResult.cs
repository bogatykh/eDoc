using System.Collections.Generic;

namespace eDocLib.Asic
{
    public class AsicReadResult
    {
        public AsicReadResult(IReadOnlyCollection<DataFile> dataFiles)
        {
            DataFiles = dataFiles;
        }

        public IReadOnlyCollection<DataFile> DataFiles { get; }
    }
}
