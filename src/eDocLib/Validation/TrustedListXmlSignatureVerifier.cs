using System.Security.Cryptography.Xml;
using System.Xml;

namespace eDocLib.Validation;

/// <summary>
/// Verifies the XML-DSig / XAdES envelope on a published TSL (enveloped signature, typical for EU LOTL and national lists).
/// </summary>
internal static class TrustedListXmlSignatureVerifier
{
    /// <summary>
    /// Verifies the last <c>ds:Signature</c> in document order (TSL convention: signature at end of <c>TrustServiceStatusList</c>).
    /// </summary>
    /// <param name="tslDocument">Must use <see cref="XmlDocument.PreserveWhitespace"/> = <c>true</c> when loading for digest correctness.</param>
    /// <param name="error">Failure message when verification fails.</param>
    public static bool TryVerify(XmlDocument tslDocument, out string? error)
    {
        ArgumentNullException.ThrowIfNull(tslDocument);
        error = null;
        var nsm = XmlDsigXmlNamespaces.ForDs(tslDocument.NameTable);
        var nodes = tslDocument.SelectNodes("//ds:Signature", nsm);
        if (nodes is null || nodes.Count == 0)
        {
            error = "TSL has no ds:Signature element.";
            return false;
        }

        for (var i = nodes.Count - 1; i >= 0; i--)
        {
            if (nodes[i] is not XmlElement sigEl)
                continue;
            try
            {
                var signedXml = new SignedXml(tslDocument);
                signedXml.LoadXml(sigEl);
                if (signedXml.CheckSignature())
                    return true;
            }
            catch (Exception ex)
            {
                error = "TSL signature verification failed: " + ex.Message;
                return false;
            }
        }

        error = "TSL XML-DSig signature did not verify.";
        return false;
    }

    /// <summary>Loads XML with whitespace preserved, then verifies.</summary>
    public static bool TryVerify(Stream tslXml, out string? error)
    {
        ArgumentNullException.ThrowIfNull(tslXml);
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.Load(tslXml);
        return TryVerify(doc, out error);
    }
}
