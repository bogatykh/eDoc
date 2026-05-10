namespace eDocLib;

/// <summary>Library-specific exception for the high-level EDOC / ASiC-E workflow surface.</summary>
public sealed class EdocException : Exception
{
    /// <summary>Initializes a new eDoc exception instance.</summary>
    /// <param name="message">Human-readable explanation.</param>
    /// <param name="kind">High-level category for host mapping/logging.</param>
    /// <param name="innerException">Underlying exception when wrapping.</param>
    public EdocException(string message, EdocFailureKind kind = EdocFailureKind.Unknown, Exception? innerException = null)
        : base(message, innerException) =>
        Kind = kind;

    /// <summary>Failure category supplied at construction.</summary>
    public EdocFailureKind Kind { get; }
}
