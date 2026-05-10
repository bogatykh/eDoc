using eDocLib.Asic.Xades;
using System.Xml;

namespace eDocLib.Asic.Container {
    /// <summary>
    /// ASiC-E signature
    /// </summary>
    internal class AsicSignature : XadesSignature
    {
        /// <summary>Initializes a new ASiC signature instance.</summary>
        internal AsicSignature(XmlDocument document)
            : base(document)
        {
        }
    }
}
