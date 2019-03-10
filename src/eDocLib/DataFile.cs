using System;
using System.IO;

namespace eDocLib
{
    public class DataFile
    {
        public DataFile(Stream stream, string name, string mimeType)
        {
            Stream = stream ?? throw new ArgumentNullException(nameof(stream));
            Name = name ?? throw new ArgumentNullException(nameof(name));
            MimeType = mimeType ?? throw new ArgumentNullException(nameof(mimeType));
        }

        public Stream Stream { get; }

        public string Name { get; }

        public string MimeType { get; }
    }
}
