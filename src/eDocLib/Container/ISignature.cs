using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace eDocLib.Container;

/// <summary>
/// XML digital signature as stored under META-INF in an ASiC-E / eDoc container.
/// </summary>
public interface ISignature
{
    /// <summary>XML <c>ds:Signature/@Id</c> attribute value (may be empty when omitted).</summary>
    string Id { get; }

    /// <summary>XML-DSig signature algorithm URI on <c>ds:SignatureMethod/@Algorithm</c>.</summary>
    string SignatureMethod { get; }

    /// <summary>Signing certificate extracted from <c>ds:KeyInfo</c> when present.</summary>
    X509Certificate? SigningCertificate { get; }

    /// <summary>Optional XAdES <c>SignerRole</c> claimed roles.</summary>
    IReadOnlyCollection<string> SignerRoles { get; }

    /// <summary>Optional XAdES <c>SignatureProductionPlace</c>; <c>null</c> when absent or unknown.</summary>
    SignatureProductionPlace? SignatureProductionPlace { get; }

    /// <summary>
    /// Serializes this signature as an XML document (typically UTF-8, with declaration).
    /// </summary>
    void WriteTo(Stream stream);
}
