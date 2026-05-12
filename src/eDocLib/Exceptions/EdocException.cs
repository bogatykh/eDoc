namespace eDocLib.Exceptions;

/// <summary>
/// Base for EDOC / ASiC-E high-level failures mapped from low-level ZIP/XML errors by
/// <c>Edoc.Open(EdocLibConfig, Stream)</c> and <c>Edoc.Open(EdocLibConfig, string)</c>.
/// </summary>
public abstract class EdocException : Exception
{
    /// <summary>Initializes a new instance for use by derived types.</summary>
    protected EdocException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}
