namespace eDocLib.Asic.Container;

/// <summary>Low-level ASiC-ZIP parse or structural failure before mapping to <see cref="EdocException"/>.</summary>
internal class AsicException : Exception
{
    /// <summary>Initializes a new ASiC exception instance.</summary>
    public AsicException()
    {
    }

    /// <summary>Initializes a new ASiC exception instance.</summary>
    /// <param name="message">Human-readable parse or validation error.</param>
    public AsicException(string message) : base(message)
    {
    }

    /// <summary>Initializes a new ASiC exception instance.</summary>
    /// <param name="message">Human-readable parse or validation error.</param>
    /// <param name="innerException">Underlying ZIP or XML failure.</param>
    public AsicException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
