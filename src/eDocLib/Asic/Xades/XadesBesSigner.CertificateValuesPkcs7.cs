using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace eDocLib.Asic.Xades;

/// <summary>Partial class: PKCS#7 certificate bundles in unsigned <c>CertificateValues</c>.</summary>
internal static partial class XadesBesSigner
{
    /// <summary>
    /// Appends <c>xades:CertificateValues</c> / <c>xades:OtherCertificate</c> / <c>xades:EncapsulatedPKIData</c>
    /// with a PKCS#7 certificate bundle (ETSI XAdES).
    /// </summary>
    public static void AppendUnsignedCertificateValuesPkcs7(XadesSignature signature, IEnumerable<X509Certificate2> certificates)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(certificates);

        var pkcs7Der = X509Pkcs7CertificateBag.ExportPkcs7(certificates);

        var owner = signature.GetSignatureOwnerDocument();
        var xadesNs = XadesSignature.XadesNamespaceUrl;
        var unsignedSigProps = EnsureUnsignedSignatureProperties(owner);
        var certValues = FindOrCreateChild(owner, unsignedSigProps, "CertificateValues", xadesNs);

        var other = owner.CreateElement(XadesSignature.XadesPrefix, "OtherCertificate", xadesNs);
        certValues.AppendChild(other);

        var enc = owner.CreateElement(XadesSignature.XadesPrefix, "EncapsulatedPKIData", xadesNs);
        enc.InnerText = Convert.ToBase64String(pkcs7Der);
        other.AppendChild(enc);
    }
}
