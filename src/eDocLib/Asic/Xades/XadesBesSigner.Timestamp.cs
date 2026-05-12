using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using eDocLib.Asic.Container;
using eDocLib.Timestamp;

namespace eDocLib.Asic.Xades;

/// <summary>Partial class: XAdES-T <c>SignatureTimeStamp</c> and related helpers.</summary>
internal static partial class XadesBesSigner
{
    /// <summary>
    /// XAdES-T: signs as BES, then requests a RFC 3161 token with SHA-256 imprint over the raw <c>SignatureValue</c> octets
    /// and embeds it under <c>xades:UnsignedProperties</c> / <c>SignatureTimeStamp</c> / <c>EncapsulatedTimeStamp</c>.
    /// </summary>
    public static async Task<AsicSignature> SignWithTimestampAsync(
        IEnumerable<IDataFile> dataFiles,
        X509Certificate2 signerCertificate,
        DateTimeOffset signingTime,
        ITimestampProvider timestampProvider,
        string signatureId = "sig-1",
        string signedPropertiesId = "SignedProperties-1",
        string signatureTimestampId = "SignatureTimeStamp-1",
        IReadOnlyList<string>? signerRoles = null,
        SignatureProductionPlace? productionPlace = null,
        CancellationToken cancellationToken = default,
        XadesRsaDigestPreference rsaDigestPreference = XadesRsaDigestPreference.Sha256)
    {
        ArgumentNullException.ThrowIfNull(dataFiles);
        ArgumentNullException.ThrowIfNull(signerCertificate);
        ArgumentNullException.ThrowIfNull(timestampProvider);
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
        var signed = (AsicSignature)prep.Complete(SignSignedInfoDigest(signerCertificate, prep.SigningProfile, signable));

        var owner = signed.GetSignatureOwnerDocument();
        var imprint = Sha256ImprintOverSignatureValue(owner);
        var tokenDer = await timestampProvider.GetTimestampAsync(imprint, cancellationToken).ConfigureAwait(false);
        AppendSignatureTimestamp(owner, tokenDer, signatureTimestampId);
        return signed;
    }

    /// <summary>
    /// XAdES-T using <see cref="TimestampResponderRegistry"/> to resolve the TSA URL from the signer (or issuer) thumbprint,
    /// instead of accepting an explicit <see cref="ITimestampProvider"/>.
    /// </summary>
    public static async Task<AsicSignature> SignWithTimestampAsync(
        IEnumerable<IDataFile> dataFiles,
        X509Certificate2 signerCertificate,
        DateTimeOffset signingTime,
        TimestampResponderRegistry timestampResponderRegistry,
        HttpClient? httpClient = null,
        string signatureId = "sig-1",
        string signedPropertiesId = "SignedProperties-1",
        string signatureTimestampId = "SignatureTimeStamp-1",
        IReadOnlyList<string>? signerRoles = null,
        SignatureProductionPlace? productionPlace = null,
        CancellationToken cancellationToken = default,
        XadesRsaDigestPreference rsaDigestPreference = XadesRsaDigestPreference.Sha256)
    {
        ArgumentNullException.ThrowIfNull(timestampResponderRegistry);
        using var tsp = timestampResponderRegistry.CreateHttpProviderOrThrow(signerCertificate, httpClient);
        return await SignWithTimestampAsync(
                dataFiles,
                signerCertificate,
                signingTime,
                tsp,
                signatureId,
                signedPropertiesId,
                signatureTimestampId,
                signerRoles,
                productionPlace,
                cancellationToken,
                rsaDigestPreference)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Requests an RFC 3161 token over SHA-256 of the current <c>ds:SignatureValue</c> octets and appends
    /// <c>xades:SignatureTimeStamp</c>. Use after <see cref="XadesBesPreparedSignature.Complete"/> (and optional LT material).
    /// </summary>
    public static async Task AppendSignatureTimestampAsync(
        AsicSignature signed,
        ITimestampProvider timestampProvider,
        string signatureTimestampId = "SignatureTimeStamp-1",
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signed);
        ArgumentNullException.ThrowIfNull(timestampProvider);

        var owner = signed.GetSignatureOwnerDocument();
        var imprint = Sha256ImprintOverSignatureValue(owner);
        var tokenDer = await timestampProvider.GetTimestampAsync(imprint, cancellationToken).ConfigureAwait(false);
        AppendSignatureTimestamp(owner, tokenDer, signatureTimestampId);
    }

    /// <summary>
    /// Same as <see cref="AppendSignatureTimestampAsync(AsicSignature, ITimestampProvider, string, CancellationToken)"/> but resolves the TSP via <paramref name="timestampResponderRegistry"/> for <paramref name="signerCertificate"/>.
    /// </summary>
    public static async Task AppendSignatureTimestampAsync(
        AsicSignature signed,
        X509Certificate2 signerCertificate,
        TimestampResponderRegistry timestampResponderRegistry,
        HttpClient? httpClient = null,
        string signatureTimestampId = "SignatureTimeStamp-1",
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signed);
        ArgumentNullException.ThrowIfNull(signerCertificate);
        ArgumentNullException.ThrowIfNull(timestampResponderRegistry);
        using var tsp = timestampResponderRegistry.CreateHttpProviderOrThrow(signerCertificate, httpClient);
        await AppendSignatureTimestampAsync(signed, tsp, signatureTimestampId, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Computes the SHA-256 imprint over SignatureValue.</summary>
    private static byte[] Sha256ImprintOverSignatureValue(XmlDocument owner) =>
        SHA256.HashData(SignatureValueReader.ReadOctetsOrThrow(owner));

    /// <summary>Appends signature timestamp.</summary>
    private static void AppendSignatureTimestamp(XmlDocument owner, byte[] timeStampTokenDer, string signatureTimestampId) =>
        AppendEncapsulatedTimestamp(owner, "SignatureTimeStamp", signatureTimestampId, timeStampTokenDer);

    /// <summary>
    /// Appends an XAdES timestamp wrapper element (for example <c>SignatureTimeStamp</c>) with a
    /// child <c>EncapsulatedTimeStamp</c> carrying the Base64-encoded RFC 3161 token, under
    /// <c>UnsignedSignatureProperties</c>.
    /// </summary>
    /// <param name="owner">Signature owner document.</param>
    /// <param name="wrapperLocalName">Local name of the wrapper element (e.g. <c>SignatureTimeStamp</c>).</param>
    /// <param name="wrapperId">Value of the wrapper element's <c>Id</c> attribute.</param>
    /// <param name="timeStampTokenDer">RFC 3161 timestamp token, DER-encoded.</param>
    private static void AppendEncapsulatedTimestamp(
        XmlDocument owner,
        string wrapperLocalName,
        string wrapperId,
        byte[] timeStampTokenDer)
    {
        var unsignedSigProps = EnsureUnsignedSignatureProperties(owner);

        var wrapper = owner.CreateElement(XadesSignature.XadesPrefix, wrapperLocalName, XadesSignature.XadesNamespaceUrl);
        wrapper.SetAttribute("Id", wrapperId);
        unsignedSigProps.AppendChild(wrapper);

        var enc = owner.CreateElement(XadesSignature.XadesPrefix, "EncapsulatedTimeStamp", XadesSignature.XadesNamespaceUrl);
        enc.InnerText = Convert.ToBase64String(timeStampTokenDer);
        wrapper.AppendChild(enc);
    }

    /// <summary>Finds qualifying properties.</summary>
    private static XmlElement FindQualifyingProperties(XmlDocument owner)
    {
        var nodes = owner.GetElementsByTagName("QualifyingProperties", XadesSignature.XadesNamespaceUrl);
        if (nodes.Count == 0 || nodes[0] is not XmlElement el)
        {
            throw new InvalidOperationException(
                "QualifyingProperties not found; cannot embed XAdES unsigned properties (timestamp, archive, certificates, revocation).");
        }

        return el;
    }

    /// <summary>Ensures unsigned signature properties.</summary>
    private static XmlElement EnsureUnsignedSignatureProperties(XmlDocument owner)
    {
        var qualifying = FindQualifyingProperties(owner);
        var ns = XadesSignature.XadesNamespaceUrl;
        var unsignedProps = FindOrCreateChild(owner, qualifying, "UnsignedProperties", ns);
        return FindOrCreateChild(owner, unsignedProps, "UnsignedSignatureProperties", ns);
    }
}
