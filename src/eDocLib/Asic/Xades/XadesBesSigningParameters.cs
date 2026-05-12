namespace eDocLib.Asic.Xades;

/// <summary>
/// XAdES-BES inputs shared by <see cref="eDocLib.Signing.EdocBasicSigningJob"/> and <see cref="eDocLib.Signing.EdocLongTermSigningJob"/>.
/// (XML identifiers, optional signer metadata, RSA digest preference).
/// </summary>
public sealed class XadesBesSigningParameters
{
    /// <summary>XML <c>Id</c> on <c>ds:Signature</c>.</summary>
    public string SignatureId { get; set; } = "sig-1";

    /// <summary>XML <c>Id</c> on <c>xades:SignedProperties</c>.</summary>
    public string SignedPropertiesId { get; set; } = "SignedProperties-1";

    /// <summary>Optional XAdES signer roles passed into prepare/sign.</summary>
    public IReadOnlyList<string>? SignerRoles { get; set; }

    /// <summary>Optional XAdES signature production place passed into prepare/sign.</summary>
    public SignatureProductionPlace? ProductionPlace { get; set; }

    /// <summary>RSA-only: digest for <c>SignatureMethod</c> and references (ECDSA keys ignore this).</summary>
    public XadesRsaDigestPreference RsaDigestPreference { get; set; } = XadesRsaDigestPreference.Sha256;
}
