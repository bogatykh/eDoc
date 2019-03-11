using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace eDocLib
{
    /// <summary>
    /// Signature
    /// </summary>
    public interface ISignature
    {
        string Id { get; }

        string SignatureMethod { get; }

        X509Certificate SigningCertificate { get; }

        IReadOnlyCollection<string> SignerRoles { get; }
    }
}
