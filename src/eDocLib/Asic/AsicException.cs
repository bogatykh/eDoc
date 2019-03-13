using System;
using System.Runtime.Serialization;

namespace eDocLib.Asic
{
    [Serializable]
    public class AsicException : Exception
    {
        public AsicException()
        {
        }

        public AsicException(string message) : base(message)
        {
        }

        public AsicException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected AsicException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}
