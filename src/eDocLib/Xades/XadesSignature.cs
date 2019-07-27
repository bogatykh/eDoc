using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace eDocLib.Xades
{
    public class XadesSignature : ISignature
    {
        public const string XmlDsigSignatureProperties = "http://uri.etsi.org/01903#SignedProperties";
        public const string XadesProofOfApproval = "http://uri.etsi.org/01903/v1.2.2#ProofOfApproval";
        public const string XadesPrefix = "xades";
        public const string XadesNamespaceUrl = "http://uri.etsi.org/01903/v1.3.2#";

        private readonly SignedXml _signedXml;

        public XadesSignature()
        {
            _signedXml = new SignedXml();
        }

        public XadesSignature(XmlDocument document)
        {
            if (document == null)
            {
                throw new ArgumentNullException(nameof(document));
            }

            _signedXml = new SignedXml();
            _signedXml.LoadXml(document.DocumentElement["Signature", SignedXml.XmlDsigNamespaceUrl]);
        }

        public string Id => _signedXml.Signature.Id;

        public string SignatureMethod => _signedXml.SignatureMethod;

        public X509Certificate SigningCertificate
        {
            get
            {
                var x509Data = _signedXml.KeyInfo.OfType<KeyInfoX509Data>().SingleOrDefault();

                if (x509Data != null)
                {
                    return x509Data.Certificates[0] as X509Certificate2;
                }

                return null;
            }
        }

        public IReadOnlyCollection<string> SignerRoles => throw new NotImplementedException();
    }
}
