using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace eDocLib.Asic.Xades;

/// <summary>Public-key family represented by a signing certificate.</summary>
public enum XadesKeyKind
{
    /// <summary>RSA PKCS#1 / PSS signing.</summary>
    Rsa,

    /// <summary>Elliptic-curve DSA (NIST curves).</summary>
    Ecdsa,
}

/// <summary>RSA digest choice when building or resolving a <see cref="XadesSigningProfile"/> from an RSA certificate (ECDSA keys ignore this).</summary>
public enum XadesRsaDigestPreference
{
    /// <summary>Use SHA-256 with RSA-SHA256 signature method and digest references.</summary>
    Sha256,

    /// <summary>Use SHA-384 with RSA-SHA384 signature method and digest references.</summary>
    Sha384,
}

/// <summary>
/// XML-DSig algorithms for XAdES-BES: <c>SignatureMethod</c>, hash over canonical <c>SignedInfo</c>, and <c>DigestMethod</c> for references.
/// </summary>
/// <param name="SignatureMethodUri"><c>ds:SignatureMethod/@Algorithm</c> URI.</param>
/// <param name="SignedInfoHashAlgorithm">Hash algorithm used when signing canonical <c>SignedInfo</c> octets.</param>
/// <param name="DigestMethodUri"><c>ds:DigestMethod/@Algorithm</c> URI for manifest references.</param>
/// <param name="KeyKind">RSA versus ECDSA branch used when constructing octet signatures.</param>
public readonly record struct XadesSigningProfile(
    string SignatureMethodUri,
    HashAlgorithmName SignedInfoHashAlgorithm,
    string DigestMethodUri,
    XadesKeyKind KeyKind)
{

    /// <summary>Creates a value from certificate.</summary>
    /// <param name="certificate">Signer certificate whose key type and parameters determine algorithms.</param>
    /// <param name="rsaDigestPreference">For RSA keys only; ECDSA profiles ignore this.</param>
    public static XadesSigningProfile FromCertificate(
        X509Certificate2 certificate,
        XadesRsaDigestPreference rsaDigestPreference = XadesRsaDigestPreference.Sha256)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        using (var rsa = certificate.GetRSAPublicKey())
        {
            if (rsa is not null)
            {
                return rsaDigestPreference switch
                {
                    XadesRsaDigestPreference.Sha256 => new XadesSigningProfile(
                        XadesSignatureAlgorithms.RsaWithSha256,
                        HashAlgorithmName.SHA256,
                        XadesSignatureAlgorithms.Sha256Digest,
                        XadesKeyKind.Rsa),
                    XadesRsaDigestPreference.Sha384 => new XadesSigningProfile(
                        XadesSignatureAlgorithms.RsaWithSha384,
                        HashAlgorithmName.SHA384,
                        XadesSignatureAlgorithms.Sha384Digest,
                        XadesKeyKind.Rsa),
                    _ => throw new ArgumentOutOfRangeException(nameof(rsaDigestPreference), rsaDigestPreference, null),
                };
            }
        }

        using var ecPub = certificate.GetECDsaPublicKey()
                          ?? throw new NotSupportedException(
                              "Certificate public key must be RSA or ECDSA (P-256, P-384, or P-521).");

        var p = ecPub.ExportParameters(false);
        var oid = p.Curve.Oid?.Value;
        var keySize = ecPub.KeySize;

        var isP256 = keySize == 256
                     || string.Equals(oid, ECCurve.NamedCurves.nistP256.Oid.Value, StringComparison.Ordinal);
        if (isP256)
        {
            return new XadesSigningProfile(
                XadesSignatureAlgorithms.EcdsaWithSha256,
                HashAlgorithmName.SHA256,
                XadesSignatureAlgorithms.Sha256Digest,
                XadesKeyKind.Ecdsa);
        }

        var isP384 = keySize == 384
                     || string.Equals(oid, ECCurve.NamedCurves.nistP384.Oid.Value, StringComparison.Ordinal);
        if (isP384)
        {
            return new XadesSigningProfile(
                XadesSignatureAlgorithms.EcdsaWithSha384,
                HashAlgorithmName.SHA384,
                XadesSignatureAlgorithms.Sha384Digest,
                XadesKeyKind.Ecdsa);
        }

        var isP521 = keySize == 521
                     || string.Equals(oid, ECCurve.NamedCurves.nistP521.Oid.Value, StringComparison.Ordinal);
        if (isP521)
        {
            return new XadesSigningProfile(
                XadesSignatureAlgorithms.EcdsaWithSha512,
                HashAlgorithmName.SHA512,
                XadesSignatureAlgorithms.Sha512Digest,
                XadesKeyKind.Ecdsa);
        }

        throw new NotSupportedException(
            $"ECDSA curve is not supported (OID '{oid}', key size {keySize}). Supported: P-256, P-384, P-521.");
    }

    /// <summary>Maps a <c>SignatureMethod</c> URI to the hash algorithm applied to <c>SignedInfo</c>.</summary>
    public static HashAlgorithmName HashAlgorithmForSignatureMethod(string signatureMethodUri) =>
        signatureMethodUri switch
        {
            XadesSignatureAlgorithms.RsaWithSha256 => HashAlgorithmName.SHA256,
            XadesSignatureAlgorithms.RsaWithSha384 => HashAlgorithmName.SHA384,
            XadesSignatureAlgorithms.EcdsaWithSha256 => HashAlgorithmName.SHA256,
            XadesSignatureAlgorithms.EcdsaWithSha384 => HashAlgorithmName.SHA384,
            XadesSignatureAlgorithms.EcdsaWithSha512 => HashAlgorithmName.SHA512,
            _ => throw new NotSupportedException($"Unsupported SignatureMethod URI: {signatureMethodUri}"),
        };

    /// <summary>Returns whether ECDSA signature method.</summary>
    public static bool IsEcdsaSignatureMethod(string signatureMethodUri) =>
        signatureMethodUri is XadesSignatureAlgorithms.EcdsaWithSha256
            or XadesSignatureAlgorithms.EcdsaWithSha384
            or XadesSignatureAlgorithms.EcdsaWithSha512;
}
