using eDocLib;

namespace eDocLib.Validation;

/// <summary>One container signature and its validation outcome.</summary>
public sealed class EdocSignatureVerification
{
    /// <summary>Zero-based signature position in the container.</summary>
    public required int Ordinal { get; init; }

    /// <summary>Signature object that was validated.</summary>
    public required ISignature Signature { get; init; }

    /// <summary>Validation result for the signature.</summary>
    public required SignatureValidationResult Result { get; init; }
}
