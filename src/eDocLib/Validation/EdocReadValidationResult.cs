using System.Linq;
using eDocLib;

namespace eDocLib.Validation;

/// <summary>
/// Per-signature verification outcome for a loaded <see cref="Edoc"/> (e.g. from <see cref="Edoc.OpenAndValidateAsync(eDocLib.Configuration.EdocLibConfig, System.IO.Stream, SignatureTrustPolicy?, System.Threading.CancellationToken)"/> or <see cref="IValidatableDocument.ValidateAsync"/>).
/// </summary>
public sealed class EdocReadValidationResult : IEdocContainerValidationResult
{
    /// <inheritdoc />
    public required Edoc Edoc { get; init; }

    /// <inheritdoc />
    public required IReadOnlyList<EdocSignatureVerification> Signatures { get; init; }

    /// <inheritdoc />
    public bool HasSignatures => Signatures.Count > 0;

    /// <inheritdoc />
    public bool AllSignaturesValid => HasSignatures && Signatures.All(s => s.Result.Success);

    /// <inheritdoc />
    public bool HasWarnings =>
        Signatures.Any(static s =>
            s.Result.GetIndication() == SignatureValidationIndication.Indeterminate);
}
