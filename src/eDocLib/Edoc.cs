using eDocLib.Asic;
using System.IO;

namespace eDocLib
{
    /// <summary>
    /// EDOC container
    /// </summary>
    public class Edoc : AsicContainer, IEdoc
    {
        public Edoc()
        {
        }

        public Edoc(Stream stream)
            : base(stream)
        {
        }
    }
}
