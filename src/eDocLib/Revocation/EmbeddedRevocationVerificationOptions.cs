using System.Security.Cryptography.X509Certificates;

namespace eDocLib.Revocation;

/// <summary>Optional tightening for <see cref="Verify.EmbeddedRevocationVerifier"/> (typically driven by <see cref="Validation.SignatureTrustPolicy"/>).</summary>
public sealed class EmbeddedRevocationVerificationOptions
{
    /// <summary>
    /// When <c>true</c>, an embedded OCSP Basic response must verify using a certificate present in the response’s
    /// <c>certs</c> field (RFC 6960). The legacy fallback that accepts a signature verified with any CA key from the
    /// established PKIX path is disabled.
    /// </summary>
    public bool RequireOcspSignatureByEmbeddedResponderOnly { get; init; }

    /// <summary>
    /// When <c>true</c>, the first certificate embedded in the OCSP response must include the id-kp-OCSPSigning EKU
    /// (1.3.6.1.5.5.7.3.9). Implies a non-empty embedded <c>certs</c> set; enforced after a successful cryptographic
    /// verification of the Basic OCSP response.
    /// </summary>
    public bool RequireEmbeddedResponderOcspSigningExtendedKeyUsage { get; init; }

    /// <summary>
    /// When <c>true</c>, the first embedded OCSP responder certificate must build a PKIX path to
    /// <see cref="ResponderChainTrustAnchors"/> (custom roots) or, when that collection is null or empty, to the
    /// operating-system trust store. <see cref="ResponderChainExtraStore"/> is added to <c>ExtraStore</c>.
    /// Revocation checks on this chain build are disabled (no network).
    /// </summary>
    public bool ValidateEmbeddedOcspResponderCertificateChain { get; init; }

    /// <summary>Optional trust roots for the responder PKIX build (typically copied from signing policy).</summary>
    public X509Certificate2Collection? ResponderChainTrustAnchors { get; init; }

    /// <summary>Optional extra intermediates for the responder PKIX build.</summary>
    public X509Certificate2Collection? ResponderChainExtraStore { get; init; }
}
