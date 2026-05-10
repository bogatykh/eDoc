using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace eDocLib.Asic.Xades;

/// <summary>
/// Shared canonicalization for SignedInfo — must match signing and verification paths.
/// </summary>
internal static class XmlDsigCanonicalization
{
    /// <summary>
    /// Re-parses the signature document and returns Exclusive C14N bytes of <c>ds:SignedInfo</c>,
    /// matching <see cref="XadesBesSigner"/> and <see cref="Validation.DetachedSignatureVerifier"/>.
    /// </summary>
    public static byte[] GetSignedInfoCanonicalBytes(XmlDocument signatureDocument)
    {
        var copy = XadesXmlDocument.Clone(signatureDocument);

        var sx = new SignedXml(copy);
        var sigEl = copy.DocumentElement ?? throw new CryptographicException("Missing signature root.");
        sx.LoadXml(sigEl);
        var si = sx.SignedInfo?.GetXml() ?? throw new CryptographicException("SignedInfo missing.");

        var transform = new XmlDsigExcC14NTransform();
        var nsDoc = XadesXmlDocument.Empty();
        nsDoc.AppendChild(nsDoc.ImportNode(si, deep: true));
        transform.LoadInput(nsDoc);
        using var ms = (MemoryStream)transform.GetOutput(typeof(MemoryStream))!;
        return ms.ToArray();
    }
}
