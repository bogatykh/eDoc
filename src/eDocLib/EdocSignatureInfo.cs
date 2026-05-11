using System.Security.Cryptography.X509Certificates;
using eDocLib.Asic.Xades;

namespace eDocLib;

/// <summary>Read-only view over a detached <see cref="XadesSignature"/> stored in a package.</summary>
public sealed class EdocSignatureInfo
{
    private readonly XadesSignature _signature;

    /// <summary>Initializes a new eDoc signature info instance.</summary>
    internal EdocSignatureInfo(XadesSignature signature) =>
        _signature = signature ?? throw new ArgumentNullException(nameof(signature));

    /// <summary>Wraps a concrete <see cref="XadesSignature"/> implementation.</summary>
    /// <exception cref="ArgumentException"><paramref name="signature"/> is not <see cref="XadesSignature"/>.</exception>
    public static EdocSignatureInfo From(ISignature signature)
    {
        ArgumentNullException.ThrowIfNull(signature);
        if (signature is not XadesSignature xs)
        {
            throw new ArgumentException("Signature must be a XAdES-backed instance.", nameof(signature));
        }

        return new EdocSignatureInfo(xs);
    }

    /// <inheritdoc cref="ISignature.Id"/>
    public string Id => _signature.Id;

    /// <inheritdoc cref="ISignature.SignatureMethod"/>
    public string SignatureMethod => _signature.SignatureMethod;

    /// <inheritdoc cref="ISignature.SigningCertificate"/>
    public X509Certificate? SigningCertificate => _signature.SigningCertificate;

    /// <inheritdoc cref="ISignature.SignerRoles"/>
    public IReadOnlyCollection<string> SignerRoles => _signature.SignerRoles;

    /// <inheritdoc cref="ISignature.SignatureProductionPlace"/>
    public SignatureProductionPlace? SignatureProductionPlace => _signature.SignatureProductionPlace;

    /// <summary>Claimed signing instant from XAdES signed properties, when present.</summary>
    public DateTimeOffset? ClaimedSigningTime => _signature.ClaimedSigningTime;

    /// <summary>Raw <c>SignatureValue</c> octets (digest signature bytes).</summary>
    public byte[] SignatureValueOctets => _signature.GetSignatureValueOctets();

    /// <summary>DER-encoded certificates from unsigned <c>CertificateValues</c>.</summary>
    public IReadOnlyList<byte[]> UnsignedCertificateValuesDer => _signature.UnsignedEncapsulatedX509Der;

    /// <summary>PKCS#7 blobs under <c>OtherCertificate</c> / <c>EncapsulatedPKIData</c>, when present.</summary>
    public IReadOnlyList<byte[]> UnsignedCertificateValuesPkcs7Der => _signature.UnsignedEncapsulatedPkcs7Der;

    /// <summary>DER-encoded OCSP responses from unsigned <c>RevocationValues</c>.</summary>
    public IReadOnlyList<byte[]> UnsignedOcspResponsesDer => _signature.UnsignedEncapsulatedOcspDer;

    /// <summary>DER-encoded CRLs from unsigned <c>RevocationValues</c>.</summary>
    public IReadOnlyList<byte[]> UnsignedCrlsDer => _signature.UnsignedEncapsulatedCrlDer;

    /// <summary>RFC 3161 tokens embedded under <c>SignatureTimeStamp</c> / <c>EncapsulatedTimeStamp</c>.</summary>
    public IReadOnlyList<byte[]> EncapsulatedTimeStampDer =>
        XadesUnsignedEmbeddedValues.ReadEncapsulatedTimeStamps(_signature.GetSignatureOwnerDocument());

    /// <summary>Coarse classification of embedded unsigned material (BES / LT / archive).</summary>
    public EdocMaterialProfile MaterialProfile => ClassifyMaterial(_signature);

    /// <summary>Classifies material.</summary>
    private static EdocMaterialProfile ClassifyMaterial(XadesSignature xs)
    {
        var doc = xs.GetSignatureOwnerDocument();
        if (doc.GetElementsByTagName("ArchiveTimeStamp", "*").Count > 0)
        {
            return EdocMaterialProfile.Archived;
        }

        if (xs.UnsignedEncapsulatedX509Der.Count > 0
            || xs.UnsignedEncapsulatedPkcs7Der.Count > 0
            || xs.UnsignedEncapsulatedOcspDer.Count > 0
            || xs.UnsignedEncapsulatedCrlDer.Count > 0)
        {
            return EdocMaterialProfile.LongTermMaterial;
        }

        return EdocMaterialProfile.Basic;
    }
}
