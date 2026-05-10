using System.Linq;
using System.Xml;

namespace eDocLib.Asic.Xades;

/// <summary>Partial class: embed OCSP/CRL DER under unsigned <c>RevocationValues</c>. See primary <see cref="XadesBesSigner"/> declaration.</summary>
internal static partial class XadesBesSigner
{
    /// <summary>
    /// Appends <c>xades:RevocationValues</c> with <c>CRLValues</c> / <c>OCSPValues</c> wrappers and base64 DER blobs
    /// (<c>EncapsulatedCRLValue</c>, <c>EncapsulatedOCSPValue</c>). Parameters are OCSP responses first, then CRLs.
    /// </summary>
    public static void AppendUnsignedRevocationValues(
        XadesSignature signature,
        IEnumerable<byte[]>? ocspResponseDer = null,
        IEnumerable<byte[]>? crlDer = null)
    {
        ArgumentNullException.ThrowIfNull(signature);

        var ocspList = ocspResponseDer?.Where(b => b is { Length: > 0 }).ToList() ?? [];
        var crlList = crlDer?.Where(b => b is { Length: > 0 }).ToList() ?? [];
        if (ocspList.Count == 0 && crlList.Count == 0)
        {
            throw new ArgumentException("At least one non-empty OCSP response or CRL DER blob is required.");
        }

        var owner = signature.GetSignatureOwnerDocument();
        var ns = XadesSignature.XadesNamespaceUrl;
        var unsignedSigProps = EnsureUnsignedSignatureProperties(owner);
        var revValues = FindOrCreateChild(owner, unsignedSigProps, "RevocationValues", ns);

        if (crlList.Count > 0)
        {
            var crlValues = FindOrCreateChild(owner, revValues, "CRLValues", ns);
            foreach (var der in crlList)
            {
                var enc = owner.CreateElement(XadesSignature.XadesPrefix, "EncapsulatedCRLValue", ns);
                enc.InnerText = Convert.ToBase64String(der);
                crlValues.AppendChild(enc);
            }
        }

        if (ocspList.Count > 0)
        {
            var ocspValues = FindOrCreateChild(owner, revValues, "OCSPValues", ns);
            foreach (var der in ocspList)
            {
                var enc = owner.CreateElement(XadesSignature.XadesPrefix, "EncapsulatedOCSPValue", ns);
                enc.InnerText = Convert.ToBase64String(der);
                ocspValues.AppendChild(enc);
            }
        }
    }
}
