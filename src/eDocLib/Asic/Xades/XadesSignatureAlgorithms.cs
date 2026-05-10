using System.Security.Cryptography.Xml;

namespace eDocLib.Asic.Xades;

/// <summary>URIs for XML-DSig algorithms used when preparing detached XAdES-BES signatures (RSA-SHA256/384, ECDSA P-256/P-384).</summary>
internal static class XadesSignatureAlgorithms
{
    /// <summary>Exclusive XML canonicalization for <c>ds:SignedInfo</c> and <c>SignedProperties</c> transform.</summary>
    public const string ExclusiveCanonicalXml = "http://www.w3.org/2001/10/xml-exc-c14n#";

    /// <summary><c>ds:SignatureMethod</c> — RSA with SHA-256 (PKCS#1 v1.5).</summary>
    public const string RsaWithSha256 = SignedXml.XmlDsigRSASHA256Url;

    /// <summary><c>ds:SignatureMethod</c> — RSA with SHA-384 (PKCS#1 v1.5).</summary>
    public const string RsaWithSha384 = SignedXml.XmlDsigRSASHA384Url;

    /// <summary><c>ds:SignatureMethod</c> — ECDSA with SHA-256 (<c>SignatureValue</c> is DER <c>SEQUENCE { r, s }</c>).</summary>
    public const string EcdsaWithSha256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";

    /// <summary><c>ds:SignatureMethod</c> — ECDSA with SHA-384.</summary>
    public const string EcdsaWithSha384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";

    /// <summary><c>ds:SignatureMethod</c> — ECDSA with SHA-512.</summary>
    public const string EcdsaWithSha512 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";

    /// <summary><c>ds:DigestMethod</c> for references — SHA-256.</summary>
    public const string Sha256Digest = SignedXml.XmlDsigSHA256Url;

    /// <summary><c>ds:DigestMethod</c> for references — SHA-384.</summary>
    public const string Sha384Digest = SignedXml.XmlDsigSHA384Url;

    /// <summary><c>ds:DigestMethod</c> for references — SHA-512.</summary>
    public const string Sha512Digest = SignedXml.XmlDsigSHA512Url;
}
