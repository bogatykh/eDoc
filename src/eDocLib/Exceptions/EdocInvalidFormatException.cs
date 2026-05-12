namespace eDocLib.Exceptions;

/// <summary>Bytes or manifest entries do not match expected EDOC / ASiC-E encoding or naming rules.</summary>
public sealed class EdocInvalidFormatException : EdocException
{
    /// <summary>Initializes a new instance with the specified message and optional inner exception.</summary>
    public EdocInvalidFormatException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}
