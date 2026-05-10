using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using eDocLib.Asic.Container;
using eDocLib.Timestamp;
using eDocLib.Asic.Xades;

namespace eDocLib;

/// <summary>
/// Two-phase XAdES-BES (or T after <see cref="CompleteWithEmbeddedMaterialAndTimestampAsync(XadesBesPreparedSignature, byte[], ITimestampProvider, string, CancellationToken)"/>), plus methods on this job to append
/// unsigned long-term material (certificate/revocation embedding) for LT profiles.
/// </summary>
public sealed class EdocLongTermSigningJob
{
    /// <summary>Stores the edoc.</summary>
    private readonly Edoc _edoc;

    /// <summary>Initializes a new eDoc long term signing job instance.</summary>
    /// <param name="edoc">Target container whose payloads are hashed for the new signature.</param>
    /// <param name="signingCertificate">Certificate whose private key signs <c>SignedInfo</c>.</param>
    /// <param name="signingTime">Claimed signing time for XAdES <c>SigningTime</c>.</param>
    public EdocLongTermSigningJob(
        Edoc edoc,
        X509Certificate2 signingCertificate,
        DateTimeOffset signingTime)
    {
        _edoc = edoc ?? throw new ArgumentNullException(nameof(edoc));
        SigningCertificate = signingCertificate ?? throw new ArgumentNullException(nameof(signingCertificate));
        SigningTime = signingTime;
    }

    /// <summary>Signer certificate supplied at construction.</summary>
    public X509Certificate2 SigningCertificate { get; }

    /// <summary>Claimed signing instant supplied at construction.</summary>
    public DateTimeOffset SigningTime { get; }

    /// <summary>XML <c>Id</c> on <c>ds:Signature</c> for <see cref="Prepare"/>.</summary>
    public string SignatureId { get; set; } = "sig-1";

    /// <summary>XML <c>Id</c> on <c>xades:SignedProperties</c> for <see cref="Prepare"/>.</summary>
    public string SignedPropertiesId { get; set; } = "SignedProperties-1";

    /// <summary>Optional XAdES signer roles passed into <see cref="Prepare"/>.</summary>
    public IReadOnlyList<string>? SignerRoles { get; set; }

    /// <summary>Optional XAdES signature production place passed into <see cref="Prepare"/>.</summary>
    public SignatureProductionPlace? ProductionPlace { get; set; }

    /// <summary>RSA-only: digest for <c>SignatureMethod</c> and references (ECDSA keys ignore this).</summary>
    public XadesRsaDigestPreference RsaDigestPreference { get; set; } = XadesRsaDigestPreference.Sha256;

    /// <summary>
    /// Issuer / CA certificates to embed after the signing certificate (no private keys required).
    /// The signing certificate is always included first when embedding.
    /// </summary>
    public IReadOnlyList<X509Certificate2> CaCertificatesToEmbed { get; set; } = Array.Empty<X509Certificate2>();

    /// <summary>
    /// Whether embedded chain material is written as individual <c>EncapsulatedX509Certificate</c> elements or as one PKCS#7 bundle.
    /// </summary>
    public CertificateValuesWireFormat CertificateValuesFormat { get; set; } = CertificateValuesWireFormat.EncapsulatedX509;

    /// <summary>DER-encoded OCSP responses embedded under unsigned <c>RevocationValues</c> after signing.</summary>
    public IReadOnlyList<byte[]> OcspDerBlobs { get; set; } = Array.Empty<byte[]>();

    /// <summary>DER-encoded CRLs embedded under unsigned <c>RevocationValues</c> after signing.</summary>
    public IReadOnlyList<byte[]> CrlDerBlobs { get; set; } = Array.Empty<byte[]>();

    /// <summary>Prepares the signature material.</summary>
    public XadesBesPreparedSignature Prepare()
    {
        _edoc.ResetPayloadStreamsIfSeekable();
        return XadesBesSigner.PrepareSign(
            _edoc.DataFiles,
            SigningCertificate,
            SigningTime,
            SignatureId,
            SignedPropertiesId,
            SignerRoles,
            ProductionPlace,
            RsaDigestPreference);
    }

    /// <summary>Finalizes the signature, embeds LT material, and attaches to the document.</summary>
    public void CompleteWithEmbeddedMaterial(XadesBesPreparedSignature prepared, ReadOnlySpan<byte> signatureValueOctets)
    {
        ArgumentNullException.ThrowIfNull(prepared);
        var sig = (AsicSignature)prepared.Complete(signatureValueOctets);
        ApplyLongTermMaterial(sig);
        _edoc.AddSignature(sig);
    }

    /// <summary>
    /// Same as <see cref="CompleteWithEmbeddedMaterial"/> then RFC 3161 <c>SignatureTimeStamp</c> over <c>SignatureValue</c>.
    /// </summary>
    public async Task CompleteWithEmbeddedMaterialAndTimestampAsync(
        XadesBesPreparedSignature prepared,
        byte[] signatureValueOctets,
        ITimestampProvider timestampProvider,
        string signatureTimestampId = "SignatureTimeStamp-1",
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(prepared);
        ArgumentNullException.ThrowIfNull(timestampProvider);
        ArgumentNullException.ThrowIfNull(signatureValueOctets);
        var sig = (AsicSignature)prepared.Complete(signatureValueOctets);
        ApplyLongTermMaterial(sig);
        await XadesBesSigner.AppendSignatureTimestampAsync(sig, timestampProvider, signatureTimestampId, cancellationToken)
            .ConfigureAwait(false);
        _edoc.AddSignature(sig);
    }

    /// <summary>
    /// Same as <see cref="CompleteWithEmbeddedMaterialAndTimestampAsync(XadesBesPreparedSignature, byte[], ITimestampProvider, string, CancellationToken)"/> but resolves RFC 3161 URL via <paramref name="timestampResponderRegistry"/> for <see cref="SigningCertificate"/>.
    /// </summary>
    public async Task CompleteWithEmbeddedMaterialAndTimestampAsync(
        XadesBesPreparedSignature prepared,
        byte[] signatureValueOctets,
        TimestampResponderRegistry timestampResponderRegistry,
        HttpClient? httpClient = null,
        string signatureTimestampId = "SignatureTimeStamp-1",
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(timestampResponderRegistry);
        using var tsp = timestampResponderRegistry.CreateHttpProviderOrThrow(SigningCertificate, httpClient);
        await CompleteWithEmbeddedMaterialAndTimestampAsync(prepared, signatureValueOctets, tsp, signatureTimestampId, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>Applies long term material.</summary>
    private void ApplyLongTermMaterial(AsicSignature sig)
    {
        var chain = new List<X509Certificate2> { SigningCertificate };
        foreach (var c in CaCertificatesToEmbed)
        {
            chain.Add(c);
        }

        XadesBesSigner.AppendUnsignedLongTermMaterial(
            sig,
            chain,
            OcspDerBlobs,
            CrlDerBlobs,
            CertificateValuesFormat);
    }
}
