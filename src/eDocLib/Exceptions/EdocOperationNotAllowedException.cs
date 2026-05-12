namespace eDocLib.Exceptions;

/// <summary>Requested operation is not permitted in the current container or validation state.</summary>
public sealed class EdocOperationNotAllowedException : EdocException
{
    /// <summary>Initializes a new instance with the specified message and optional inner exception.</summary>
    public EdocOperationNotAllowedException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}
