namespace eDocLib.Exceptions;

/// <summary>Recognized container shell but ZIP or XML layout violates structural rules (including invalid ZIP bytes).</summary>
public sealed class EdocInvalidStructureException : EdocException
{
    /// <summary>Initializes a new instance with the specified message and optional inner exception.</summary>
    public EdocInvalidStructureException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}
