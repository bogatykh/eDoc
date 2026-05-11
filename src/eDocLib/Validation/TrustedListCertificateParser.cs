using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;
using eDocLib.Tsl.Xml;

namespace eDocLib.Validation;

/// <summary>
/// Extracts DER certificates from ETSI TS 119 612 TSL XML (<c>TrustServiceStatusList</c>, namespace <c>http://uri.etsi.org/02231/v2#</c>).
/// Does not validate TSL signatures or service semantics — only collects <c>X509Certificate</c> elements.
/// </summary>
internal static class TrustedListCertificateParser
{
    /// <summary>ETSI TSL namespace alias.</summary>
    private static readonly XNamespace TslNs = TslXmlNamespace.Tsl;

    /// <summary>
    /// Reads all <c>X509Certificate</c> children (any depth), decodes base64 DER, skips invalid entries.
    /// Caller owns the returned collection and must dispose certificates when done.
    /// </summary>
    public static X509Certificate2Collection ReadCertificates(Stream tslXml)
    {
        ArgumentNullException.ThrowIfNull(tslXml);
        var doc = XDocument.Load(tslXml, LoadOptions.PreserveWhitespace);
        var byThumb = new Dictionary<string, X509Certificate2>(StringComparer.OrdinalIgnoreCase);
        foreach (var el in doc.Descendants(TslNs + "X509Certificate"))
        {
            var text = TslXmlText.CollapseBase64Whitespace(el.Value);
            if (text.Length == 0)
                continue;

            byte[] raw;
            try
            {
                raw = Convert.FromBase64String(text);
            }
            catch (FormatException)
            {
                continue;
            }

            X509Certificate2 cert;
            try
            {
                cert = new X509Certificate2(raw);
            }
            catch (CryptographicException)
            {
                continue;
            }

            var thumb = cert.Thumbprint;
            if (byThumb.ContainsKey(thumb))
            {
                cert.Dispose();
                continue;
            }

            byThumb.Add(thumb, cert);
        }

        var col = new X509Certificate2Collection();
        foreach (var c in byThumb.Values)
            col.Add(c);
        return col;
    }
}
