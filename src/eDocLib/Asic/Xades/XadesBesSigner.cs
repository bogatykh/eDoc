using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using eDocLib.Asic.Container;

namespace eDocLib.Asic.Xades;

/// <summary>
/// Builds XAdES-BES detached signatures for ASiC-E payloads (one <c>ds:Reference</c> per data file by relative path).
/// Strategy: explicit XML-DSig construction; RSA-SHA256 (default) or RSA-SHA384 (optional), or ECDSA-SHA256 (P-256) / ECDSA-SHA384 (P-384); XAdES <c>SigningTime</c> in <c>QualifyingProperties</c>.
/// Call <c>SignWithTimestampAsync</c> with an <see cref="eDocLib.Timestamp.ITimestampProvider"/> or <see cref="eDocLib.Timestamp.TimestampResponderRegistry"/> to produce XAdES-T (<c>SignatureTimeStamp</c> over SHA-256 of raw <c>SignatureValue</c> bytes).
/// </summary>
internal static partial class XadesBesSigner
{
    private const string DsNs = SignedXml.XmlDsigNamespaceUrl;

    /// <summary>
    /// Builds a BES signature document with placeholder <c>SignatureValue</c>. Does not require a private key on
    /// <paramref name="signerCertificate"/> (public certificate is enough for <c>KeyInfo</c>).
    /// Sign <see cref="XadesBesPreparedSignature.GetSignableBytes"/> externally, then <see cref="XadesBesPreparedSignature.Complete"/>.
    /// </summary>
    public static XadesBesPreparedSignature PrepareSign(
        IEnumerable<IDataFile> dataFiles,
        X509Certificate2 signerCertificate,
        DateTimeOffset signingTime,
        string signatureId = "sig-1",
        string signedPropertiesId = "SignedProperties-1",
        IReadOnlyList<string>? signerRoles = null,
        SignatureProductionPlace? productionPlace = null,
        XadesRsaDigestPreference rsaDigestPreference = XadesRsaDigestPreference.Sha256)
    {
        ArgumentNullException.ThrowIfNull(dataFiles);
        ArgumentNullException.ThrowIfNull(signerCertificate);

        var profile = XadesSigningProfile.FromCertificate(signerCertificate, rsaDigestPreference);
        var fileEntries = ReadPayloadEntries(dataFiles);
        var normalized = CreateNormalizedBesSignatureDom(
            fileEntries,
            signerCertificate,
            signingTime,
            signatureId,
            signedPropertiesId,
            signerRoles,
            productionPlace,
            profile);
        return new XadesBesPreparedSignature(normalized, profile);
    }

    /// <summary>
    /// Same as the parameterised <see cref="PrepareSign(IEnumerable{IDataFile}, X509Certificate2, DateTimeOffset, string, string, IReadOnlyList{string}?, SignatureProductionPlace?, XadesRsaDigestPreference)"/> overload,
    /// reading XML ids, roles, production place, and RSA digest preference from <paramref name="parameters"/>.
    /// </summary>
    public static XadesBesPreparedSignature PrepareSign(
        IEnumerable<IDataFile> dataFiles,
        X509Certificate2 signerCertificate,
        DateTimeOffset signingTime,
        XadesBesSigningParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        return PrepareSign(
            dataFiles,
            signerCertificate,
            signingTime,
            parameters.SignatureId,
            parameters.SignedPropertiesId,
            parameters.SignerRoles,
            parameters.ProductionPlace,
            parameters.RsaDigestPreference);
    }

    /// <summary>
    /// Creates a detached signature covering all <paramref name="dataFiles"/> by <see cref="IDataFile.Name"/> URI.
    /// Streams are read from the current position to end; positions are not reset.
    /// </summary>
    /// <param name="dataFiles">Payload files to reference from the detached signature.</param>
    /// <param name="signerCertificate">Certificate with private key used to sign <c>SignedInfo</c>.</param>
    /// <param name="signingTime">UTC signing time written into XAdES signed properties.</param>
    /// <param name="signatureId">Identifier assigned to the <c>ds:Signature</c> element.</param>
    /// <param name="signedPropertiesId">Identifier assigned to the XAdES signed properties element.</param>
    /// <param name="signerRoles">Optional XAdES <c>ClaimedRole</c> strings (placed under <c>SignerRole</c>).</param>
    /// <param name="productionPlace">Optional XAdES <c>SignatureProductionPlace</c>.</param>
    /// <param name="rsaDigestPreference">Digest algorithm preference for RSA certificates.</param>
    internal static AsicSignature Sign(
        IEnumerable<IDataFile> dataFiles,
        X509Certificate2 signerCertificate,
        DateTimeOffset signingTime,
        string signatureId = "sig-1",
        string signedPropertiesId = "SignedProperties-1",
        IReadOnlyList<string>? signerRoles = null,
        SignatureProductionPlace? productionPlace = null,
        XadesRsaDigestPreference rsaDigestPreference = XadesRsaDigestPreference.Sha256)
    {
        ArgumentNullException.ThrowIfNull(signerCertificate);
        if (!signerCertificate.HasPrivateKey)
        {
            throw new ArgumentException("Certificate must include a private key.", nameof(signerCertificate));
        }

        var prep = PrepareSign(
            dataFiles,
            signerCertificate,
            signingTime,
            signatureId,
            signedPropertiesId,
            signerRoles,
            productionPlace,
            rsaDigestPreference);
        var signable = prep.GetSignableBytes();
        var signatureBytes = SignSignedInfoDigest(signerCertificate, prep.SigningProfile, signable);
        return (AsicSignature)prep.Complete(signatureBytes);
    }
}
