using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace eDocLib.Asic
{
    /// <summary>
    /// ASiC-E signature
    /// </summary>
    public class AsicSignature : ISignature
    {
        public string Id => throw new NotImplementedException();

        public string SignatureMethod => throw new NotImplementedException();

        public X509Certificate SigningCertificate => throw new NotImplementedException();

        public IReadOnlyCollection<string> SignerRoles => throw new NotImplementedException();
    }
}
