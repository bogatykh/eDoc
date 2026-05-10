using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;
using eDocLib.Asic.Container;

namespace eDocLib.Asic.Xades;

/// <summary>
/// Result of the prepare-sign step (<see cref="EdocBasicSigningJob.Prepare"/>, long-term jobs): XAdES-BES structure with placeholder <c>SignatureValue</c>, ready for
/// external signing of <see cref="GetSignableBytes"/>.
/// </summary>
public sealed class XadesBesPreparedSignature
{
    /// <summary>Stores the normalized dom.</summary>
    private readonly XmlDocument _normalizedDom;

    /// <summary>Initializes a new XAdES BES prepared signature instance.</summary>
    internal XadesBesPreparedSignature(XmlDocument normalizedDom, XadesSigningProfile signingProfile)
    {
        _normalizedDom = normalizedDom ?? throw new ArgumentNullException(nameof(normalizedDom));
        SigningProfile = signingProfile;
    }

    /// <summary>
    /// Algorithms used to build this prepared signature (digest/signature methods aligned with the prepared XML).
    /// Pass this to signing helpers together with <see cref="GetSignableBytes"/> when completing via <see cref="Complete"/>.
    /// </summary>
    public XadesSigningProfile SigningProfile { get; }

    /// <summary>URI from <c>ds:SignatureMethod/@Algorithm</c> in the prepared document.</summary>
    public string SignatureMethodUri => ReadSignatureMethodUri(_normalizedDom);

    /// <summary>Hash algorithm for <c>SignData</c> / <c>VerifyData</c> over the canonical <c>ds:SignedInfo</c> octets.</summary>
    public HashAlgorithmName SignedInfoHashAlgorithm =>
        XadesSigningProfile.HashAlgorithmForSignatureMethod(SignatureMethodUri);

    /// <summary>When <c>true</c>, use <see cref="DSASignatureFormat.Rfc3279DerSequence"/> for ECDSA signature octets.</summary>
    public bool UsesEcdsaSignatureFormat => XadesSigningProfile.IsEcdsaSignatureMethod(SignatureMethodUri);

    /// <summary>Reads signature method URI.</summary>
    private static string ReadSignatureMethodUri(XmlDocument dom)
    {
        var nodes = dom.GetElementsByTagName("SignatureMethod", SignedXml.XmlDsigNamespaceUrl);
        if (nodes.Count == 0 || nodes[0] is not XmlElement el)
        {
            throw new InvalidOperationException("ds:SignatureMethod is missing.");
        }

        var alg = el.GetAttribute("Algorithm");
        if (string.IsNullOrEmpty(alg))
        {
            throw new InvalidOperationException("ds:SignatureMethod/@Algorithm is missing.");
        }

        return alg;
    }

    /// <summary>
    /// Octets to pass to the signer's API after exclusive-C14N over <c>ds:SignedInfo</c>: RSA PKCS#1 v1.5 or ECDSA DER <c>r,s</c>
    /// (see <see cref="SignatureMethodUri"/> / <see cref="UsesEcdsaSignatureFormat"/>).
    /// </summary>
    public byte[] GetSignableBytes()
    {
        var sig = new AsicSignature(CloneDom());
        var owner = sig.GetSignatureOwnerDocument();
        return XmlDsigCanonicalization.GetSignedInfoCanonicalBytes(owner);
    }

    /// <summary>Materializes a detached XAdES signature after embedding raw <c>SignatureValue</c> octets (RSA PKCS#1 or ECDSA DER).</summary>
    public ISignature Complete(ReadOnlySpan<byte> signatureValueOctets)
    {
        if (signatureValueOctets.IsEmpty)
        {
            throw new ArgumentException("Signature value must not be empty.", nameof(signatureValueOctets));
        }

        var copy = CloneDom();
        var sig = new AsicSignature(copy);
        var owner = sig.GetSignatureOwnerDocument();
        var ns = SignedXml.XmlDsigNamespaceUrl;
        var nodes = owner.GetElementsByTagName("SignatureValue", ns);
        if (nodes.Count == 0 || nodes[0] is not XmlElement el)
        {
            throw new InvalidOperationException("SignatureValue element missing.");
        }

        el.InnerText = Convert.ToBase64String(signatureValueOctets);
        return sig;
    }

    /// <summary>Clones DOM.</summary>
    private XmlDocument CloneDom() => XadesXmlDocument.Clone(_normalizedDom);
}
