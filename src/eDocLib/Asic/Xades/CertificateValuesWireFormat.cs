namespace eDocLib.Asic.Xades;

/// <summary>
/// How embedded signer-chain material is written under XAdES <c>xades:CertificateValues</c>.
/// </summary>
public enum CertificateValuesWireFormat
{
    /// <summary>One <c>xades:EncapsulatedX509Certificate</c> per certificate (DER, Base64).</summary>
    EncapsulatedX509,

    /// <summary>
    /// PKCS#7 certificate-only bundle under <c>xades:OtherCertificate</c> / <c>xades:EncapsulatedPKIData</c> (ETSI XAdES).
    /// </summary>
    Pkcs7,
}
