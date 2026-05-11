using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using eDocLib.Asic.Xades;

namespace eDocLib.Validation;

/// <summary>
/// Verifies XAdES <c>SigningCertificate</c> / <c>CertDigest</c> + <c>IssuerSerial</c> against the signing certificate from <c>KeyInfo</c>.
/// </summary>
internal static class SigningCertificateDigestVerifier
{
    /// <summary>
    /// When <c>xades:SigningCertificate</c> is absent: succeeds unless <paramref name="requireElement"/> is <c>true</c>.
    /// When present: requires at least one <c>xades:Cert</c> whose digest and issuer/serial match <paramref name="signingCertificate"/>.
    /// </summary>
    /// <param name="signatureDocument">Signature XML document to inspect.</param>
    /// <param name="signingCertificate">Certificate from <c>KeyInfo</c> that must match the XAdES reference.</param>
    /// <param name="requireElement">When <c>true</c>, a missing <c>xades:SigningCertificate</c> fails validation.</param>
    /// <param name="error">Failure message when validation fails.</param>
    /// <param name="signatureRootScope">
    /// Optional <c>ds:Signature</c> element; when set, only descendants of this subtree are considered (avoids picking up
    /// <c>SigningCertificate</c> from another signature in the same document). When <c>null</c>, searches the whole document.
    /// </param>
    /// <param name="allowSha384CertDigest">
    /// When <c>false</c>, SHA-384 <c>CertDigest</c> is rejected. Default <c>true</c>.
    /// </param>
    /// <param name="allowSha512CertDigest">
    /// When <c>false</c>, SHA-512 <c>CertDigest</c> is rejected. Default <c>true</c>.
    /// </param>
    public static bool TryVerifyIfPresent(
        XmlDocument signatureDocument,
        X509Certificate2 signingCertificate,
        bool requireElement,
        out string? error,
        XmlElement? signatureRootScope = null,
        bool allowSha384CertDigest = true,
        bool allowSha512CertDigest = true)
    {
        ArgumentNullException.ThrowIfNull(signatureDocument);
        ArgumentNullException.ThrowIfNull(signingCertificate);

        error = null;
        var nsm = XadesNamespaceManager(signatureDocument);
        var certXPath = signatureRootScope is null
            ? "//xades:SigningCertificate/xades:Cert"
            : ".//xades:SigningCertificate/xades:Cert";
        var wrapperXPath = signatureRootScope is null
            ? "//xades:SigningCertificate"
            : ".//xades:SigningCertificate";

        var certNodes = signatureRootScope is null
            ? signatureDocument.SelectNodes(certXPath, nsm)
            : signatureRootScope.SelectNodes(certXPath, nsm);
        var count = certNodes?.Count ?? 0;
        if (count == 0)
        {
            var hasWrapper = signatureRootScope is null
                ? signatureDocument.SelectSingleNode(wrapperXPath, nsm) is not null
                : signatureRootScope.SelectSingleNode(wrapperXPath, nsm) is not null;
            if (hasWrapper)
            {
                error = "xades:SigningCertificate is present but contains no xades:Cert entries.";
                return false;
            }

            if (requireElement)
            {
                error = "Policy requires xades:SigningCertificate but it is missing.";
                return false;
            }

            return true;
        }

        for (var i = 0; i < count; i++)
        {
            if (certNodes![i] is not XmlElement certEl)
            {
                continue;
            }

            if (TryMatchCertElement(certEl, signingCertificate, nsm, allowSha384CertDigest, allowSha512CertDigest, out error))
            {
                error = null;
                return true;
            }
        }

        error ??= "xades:SigningCertificate does not match the KeyInfo signing certificate (digest or IssuerSerial).";
        return false;
    }

    /// <summary>Attempts to match cert element.</summary>
    private static bool TryMatchCertElement(
        XmlElement certEl,
        X509Certificate2 signingCertificate,
        XmlNamespaceManager nsm,
        bool allowSha384CertDigest,
        bool allowSha512CertDigest,
        out string? error)
    {
        error = null;
        var digestMethod = certEl.SelectSingleNode("xades:CertDigest/ds:DigestMethod", nsm) as XmlElement;
        var digestValue = certEl.SelectSingleNode("xades:CertDigest/ds:DigestValue", nsm) as XmlElement;
        if (digestMethod == null || digestValue == null)
        {
            error = "xades:Cert is missing CertDigest/DigestMethod or DigestValue.";
            return false;
        }

        var alg = digestMethod.GetAttribute("Algorithm");
        var isSha256 = string.Equals(alg, SignedXml.XmlDsigSHA256Url, StringComparison.Ordinal);
        var isSha384 = string.Equals(alg, SignedXml.XmlDsigSHA384Url, StringComparison.Ordinal);
        var isSha512 = string.Equals(alg, SignedXml.XmlDsigSHA512Url, StringComparison.Ordinal);
        if (!isSha256 && !isSha384 && !isSha512)
        {
            error = $"SigningCertificate CertDigest uses unsupported DigestMethod: {alg}";
            return false;
        }

        if (isSha384 && !allowSha384CertDigest)
        {
            error = "Policy requires SigningCertificate CertDigest to use SHA-256 only.";
            return false;
        }

        if (isSha512 && !allowSha512CertDigest)
        {
            error = "Policy requires SigningCertificate CertDigest to use SHA-256 only.";
            return false;
        }

        byte[] expectedDigest;
        try
        {
            expectedDigest = Convert.FromBase64String(digestValue.InnerText.Trim());
        }
        catch (FormatException)
        {
            error = "SigningCertificate CertDigest DigestValue is not valid Base64.";
            return false;
        }

        var actualDigest = isSha256
            ? SHA256.HashData(signingCertificate.RawData)
            : isSha384
                ? SHA384.HashData(signingCertificate.RawData)
                : SHA512.HashData(signingCertificate.RawData);
        if (!CryptographicOperations.FixedTimeEquals(actualDigest, expectedDigest))
        {
            error = "SigningCertificate CertDigest does not match the DER encoding of the KeyInfo certificate.";
            return false;
        }

        var issuerSerial = certEl.SelectSingleNode("xades:IssuerSerial", nsm) as XmlElement;
        if (issuerSerial == null)
        {
            error = "xades:Cert is missing IssuerSerial.";
            return false;
        }

        var issuerNameEl = issuerSerial.SelectSingleNode("ds:X509IssuerName", nsm) as XmlElement;
        var serialEl = issuerSerial.SelectSingleNode("ds:X509SerialNumber", nsm) as XmlElement;
        if (issuerNameEl == null || serialEl == null)
        {
            error = "xades:IssuerSerial is missing X509IssuerName or X509SerialNumber.";
            return false;
        }

        var issuerXml = issuerNameEl.InnerText.Trim();
        var serialXml = serialEl.InnerText.Trim();
        if (!SerialMatches(signingCertificate, serialXml))
        {
            error = "SigningCertificate IssuerSerial serial number does not match the KeyInfo certificate.";
            return false;
        }

        if (!IssuerMatches(signingCertificate, issuerXml))
        {
            error = "SigningCertificate IssuerSerial issuer name does not match the KeyInfo certificate.";
            return false;
        }

        return true;
    }

    /// <summary>Returns whether certificate serial numbers match.</summary>
    private static bool SerialMatches(X509Certificate2 cert, string serialDecimalXml)
    {
        if (!BigInteger.TryParse(serialDecimalXml, NumberStyles.Integer, CultureInfo.InvariantCulture, out var fromXml))
        {
            return false;
        }

        var le = cert.GetSerialNumber();
        if (le.Length == 0)
        {
            return fromXml == 0;
        }

        var fromCert = new BigInteger(le.AsSpan(), isUnsigned: true, isBigEndian: false);
        return fromXml == fromCert;
    }

    /// <summary>Returns whether suer matches.</summary>
    private static bool IssuerMatches(X509Certificate2 cert, string issuerFromXml)
    {
        try
        {
            var a = new X500DistinguishedName(cert.Issuer);
            var b = new X500DistinguishedName(issuerFromXml);
            return a.RawData.AsSpan().SequenceEqual(b.RawData);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>Creates an XML namespace manager for XAdES lookups.</summary>
    private static XmlNamespaceManager XadesNamespaceManager(XmlDocument doc) =>
        XadesXmlNamespaces.ForXadesAndDs(doc.NameTable ?? new NameTable());
}
