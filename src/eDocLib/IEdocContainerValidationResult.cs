using eDocLib.Validation;

namespace eDocLib;

/// <summary>
/// Aggregate outcome of verifying every detached signature on an <see cref="Edoc"/> (same data as <see cref="EdocReadValidationResult"/>).
/// Use this abstraction when consumers should not depend on the concrete result type.
/// </summary>
public interface IEdocContainerValidationResult
{
    /// <summary>Container instance that was validated (caller retains ownership / dispose rules).</summary>
    Edoc Edoc { get; }

    /// <summary>Per-signature verification rows in signing order.</summary>
    IReadOnlyList<EdocSignatureVerification> Signatures { get; }

    /// <summary>Whether the container contained at least one signature entry.</summary>
    bool HasSignatures { get; }

    /// <summary>
    /// <c>true</c> when there is at least one signature and every entry passed cryptographic/policy checks.
    /// When there are no signatures, this is <c>false</c>.
    /// </summary>
    bool AllSignaturesValid { get; }

    /// <summary>
    /// <c>true</c> when at least one signature has <see cref="SignatureValidationIndication.Indeterminate"/>:
    /// XML-DSig digest/signature checks passed but overall validation did not succeed (trust, PKIX, timestamp policy, etc.).
    /// For full detail use <see cref="M:eDocLib.EdocValidation.BuildValidationReport(eDocLib.EdocReadValidationResult,eDocLib.Validation.SignatureTrustPolicy)"/>.
    /// </summary>
    bool HasWarnings { get; }
}
