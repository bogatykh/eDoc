namespace eDocLib.Validation.Reporting;

/// <summary>High-level signature profile for validation reporting (BASIC vs LT-style material, etc.).</summary>
public enum SignatureProfile
{
    /// <summary>Basic signature without additional qualified or archive material.</summary>
    BasicSignature,

    /// <summary>Signature with qualification evidence.</summary>
    QualifiedSignature,

    /// <summary>Signature profile could not be determined.</summary>
    UnknownSignature,
}
