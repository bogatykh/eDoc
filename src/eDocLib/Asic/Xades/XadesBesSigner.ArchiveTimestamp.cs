using System.Security.Cryptography;
using System.Text;
using System.Xml;
using eDocLib.Asic.Container;

namespace eDocLib.Asic.Xades;

/// <summary>Partial class: archive time-stamp imprint computation and <c>ArchiveTimeStamp</c> embedding.</summary>
internal static partial class XadesBesSigner
{
    /// <summary>
    /// Same as <see cref="ComputeDefaultArchiveTimestampImprintSha256(XmlDocument)"/> using the detached signature owner document.
    /// </summary>
    public static byte[] ComputeDefaultArchiveTimestampImprintSha256(AsicSignature signed)
    {
        ArgumentNullException.ThrowIfNull(signed);
        return ComputeDefaultArchiveTimestampImprintSha256(signed.GetSignatureOwnerDocument());
    }

    /// <summary>
    /// SHA-256 imprint for RFC 3161 archive time-stamping: hashes UTF-8 bytes of the root <c>ds:Signature</c> element’s serialized outer XML
    /// as it exists **before** appending the next token — therefore prior <c>xades:ArchiveTimeStamp</c> nodes are included when chaining.
    /// Ensures <c>xades:UnsignedSignatureProperties</c> exists when appropriate so the digest matches verification after stripping archive tokens.
    /// Uses the live DOM as normalized by <see cref="XadesSignature"/> / <see cref="AsicSignature"/> (typically after <see cref="System.Security.Cryptography.Xml.SignedXml.LoadXml"/>).
    /// Strict ETSI profiles may require C14N or different digests; hosts can pass a custom imprint to <see cref="EdocArchiveSigningJob.AppendArchiveTimeStampAsync"/> instead.
    /// </summary>
    public static byte[] ComputeDefaultArchiveTimestampImprintSha256(XmlDocument signatureOwnerDocument)
    {
        ArgumentNullException.ThrowIfNull(signatureOwnerDocument);
        RemoveUnsignedSignaturePropertiesIfNoElementChildren(signatureOwnerDocument);
        EnsureUnsignedSignatureProperties(signatureOwnerDocument);
        var root = signatureOwnerDocument.DocumentElement
                   ?? throw new InvalidOperationException("Signature XML document has no root element.");
        return SHA256.HashData(Encoding.UTF8.GetBytes(root.OuterXml));
    }

    /// <summary>
    /// After stripping archive tokens, <c>UnsignedSignatureProperties</c> may be empty but serialize differently than a freshly
    /// created shell (self-closing vs explicit empty tags). Removing the empty shell lets <see cref="EnsureUnsignedSignatureProperties"/>
    /// recreate the same shape as the first archive digest input.
    /// </summary>
    private static void RemoveUnsignedSignaturePropertiesIfNoElementChildren(XmlDocument owner)
    {
        var nsm = XadesXmlNamespaces.ForXades(owner.NameTable);
        var usp = owner.SelectSingleNode("//xades:UnsignedSignatureProperties", nsm) as XmlElement;
        if (usp is null)
        {
            return;
        }

        foreach (XmlNode n in usp.ChildNodes)
        {
            if (n is XmlElement)
            {
                return;
            }
        }

        usp.ParentNode?.RemoveChild(usp);
    }

    /// <summary>
    /// Appends <c>xades:ArchiveTimeStamp</c> with a DER RFC 3161 token under <c>UnsignedSignatureProperties</c> (XAdES-A / LTA).
    /// The token’s message imprint and binding to prior signed data are host-defined; this only embeds the token.
    /// </summary>
    public static void AppendArchiveTimeStamp(AsicSignature signed, byte[] timeStampTokenDer, string archiveTimeStampId = "ArchiveTimeStamp-1")
    {
        ArgumentNullException.ThrowIfNull(signed);
        ArgumentNullException.ThrowIfNull(timeStampTokenDer);
        AppendArchiveTimeStamp(signed.GetSignatureOwnerDocument(), timeStampTokenDer, archiveTimeStampId);
    }

    /// <summary>Appends archive time stamp.</summary>
    private static void AppendArchiveTimeStamp(XmlDocument owner, byte[] timeStampTokenDer, string archiveTimeStampId)
    {
        var unsignedSigProps = EnsureUnsignedSignatureProperties(owner);

        var arch = owner.CreateElement(XadesSignature.XadesPrefix, "ArchiveTimeStamp", XadesSignature.XadesNamespaceUrl);
        arch.SetAttribute("Id", archiveTimeStampId);
        unsignedSigProps.AppendChild(arch);

        var enc = owner.CreateElement(XadesSignature.XadesPrefix, "EncapsulatedTimeStamp", XadesSignature.XadesNamespaceUrl);
        enc.InnerText = Convert.ToBase64String(timeStampTokenDer);
        arch.AppendChild(enc);
    }
}
