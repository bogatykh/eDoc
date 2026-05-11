using System;
using System.IO;

namespace eDocLib
{
    /// <summary>Concrete payload entry; host code obtains instances via <see cref="IContainer.AddDataFile"/> or from <see cref="IContainer.DataFiles"/> after load.</summary>
    internal sealed class DataFile : IDataFile
    {
        /// <summary>Initializes a new data file instance.</summary>
        internal DataFile(Stream stream, string name, string mimeType, bool disposeStreamWithContainer = false)
            : this(stream, name, disposeStreamWithContainer)
        {
            MimeType = mimeType ?? throw new ArgumentNullException(nameof(mimeType));
        }

        /// <summary>Initializes a new data file instance.</summary>
        internal DataFile(Stream stream, string name, bool disposeStreamWithContainer = false)
        {
            Stream = stream ?? throw new ArgumentNullException(nameof(stream));
            Name = name ?? throw new ArgumentNullException(nameof(name));
            MimeType = System.Net.Mime.MediaTypeNames.Application.Octet;
            DisposeStreamWithContainer = disposeStreamWithContainer;
        }

        /// <summary>Gets the stream.</summary>
        public Stream Stream { get; }

        /// <summary>Gets the name.</summary>
        public string Name { get; }

        /// <summary>Declared media type; set at construction or by the container when known.</summary>
        public string MimeType { get; internal set; }

        /// <summary>
        /// When <c>true</c>, <see cref="Edoc.Dispose"/> releases the payload <see cref="Stream"/>
        /// (files opened from an ASiC ZIP). Caller-supplied streams default to <c>false</c>.
        /// </summary>
        internal bool DisposeStreamWithContainer { get; }
    }
}
