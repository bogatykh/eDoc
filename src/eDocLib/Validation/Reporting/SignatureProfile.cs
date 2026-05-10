namespace eDocLib.Validation.Reporting;

/// <summary>High-level signature profile (BASIC, LT-style material, LTA, etc.).</summary>
public enum SignatureProfile
{
    /// <summary>Basic signature without additional qualified or archive material.</summary>
    BasicSignature,

    /// <summary>Signature with qualification evidence.</summary>
    QualifiedSignature,

    /// <summary>Signature with archive timestamp material.</summary>
    ArchivedSignature,

    /// <summary>Signature profile outside the known reporting categories.</summary>
    ProprietarySignature,

    /// <summary>Signature profile could not be determined.</summary>
    UnknownSignature,
}
