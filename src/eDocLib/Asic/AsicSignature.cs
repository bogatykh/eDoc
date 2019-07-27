using eDocLib.Xades;
using System.Xml;

namespace eDocLib.Asic
{
    /// <summary>
    /// ASiC-E signature
    /// </summary>
    public class AsicSignature : XadesSignature
    {
        public AsicSignature(XmlDocument document)
            : base(document)
        {
        }
    }
}
