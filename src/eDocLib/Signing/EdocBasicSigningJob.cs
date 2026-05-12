using System.Security.Cryptography.X509Certificates;
using eDocLib;
using eDocLib.Asic.Xades;

namespace eDocLib.Signing;

/// <summary>
/// Two-phase XAdES-BES signing against the current payload set of an <see cref="Edoc"/>.
/// </summary>
public sealed class EdocBasicSigningJob
{
    private readonly Edoc _package;

    /// <summary>Initializes a new eDoc basic signing job instance.</summary>
    /// <param name="package">Target container whose current payloads will be digested.</param>
    /// <param name="signingCertificate">Certificate whose private key signs <c>SignedInfo</c>.</param>
    /// <param name="signingTime">Claimed signing time placed in XAdES <c>SigningTime</c>.</param>
    public EdocBasicSigningJob(
        Edoc package,
        X509Certificate2 signingCertificate,
        DateTimeOffset signingTime)
    {
        _package = package ?? throw new ArgumentNullException(nameof(package));
        SigningCertificate = signingCertificate ?? throw new ArgumentNullException(nameof(signingCertificate));
        SigningTime = signingTime;
    }

    /// <summary>Signer certificate supplied at construction.</summary>
    public X509Certificate2 SigningCertificate { get; }

    /// <summary>Claimed signing instant supplied at construction.</summary>
    public DateTimeOffset SigningTime { get; }

    /// <summary>Mutable XAdES-BES parameters (signature element ids, optional metadata, RSA digest preference).</summary>
    public XadesBesSigningParameters Xades { get; } = new();

    /// <summary>Prepares the signature material.</summary>
    public XadesBesPreparedSignature Prepare()
    {
        _package.ResetPayloadStreamsIfSeekable();
        return XadesBesSigner.PrepareSign(_package.DataFiles, SigningCertificate, SigningTime, Xades);
    }

    /// <summary>Finalizes octets from <see cref="Prepare"/> and attaches the signature to the package.</summary>
    public void Complete(XadesBesPreparedSignature prepared, ReadOnlySpan<byte> signatureValueOctets)
    {
        ArgumentNullException.ThrowIfNull(prepared);
        var sig = prepared.Complete(signatureValueOctets);
        _package.AddSignature(sig);
    }
}
