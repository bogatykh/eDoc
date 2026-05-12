namespace eDocLib.Exceptions;

/// <summary>Unclassified EDOC workflow failure; inspect <see cref="Exception.Message"/> and <see cref="Exception.InnerException"/>.</summary>
public sealed class EdocUnknownException : EdocException
{
    /// <summary>Initializes a new instance with the specified message and optional inner exception.</summary>
    public EdocUnknownException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}
