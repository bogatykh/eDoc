namespace eDocLib.Exceptions;

/// <summary>File or stream I/O failure when opening or reading an EDOC package (or path on disk).</summary>
public sealed class EdocIOException : EdocException
{
    /// <summary>Initializes a new instance with the specified message and optional inner exception.</summary>
    public EdocIOException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}
