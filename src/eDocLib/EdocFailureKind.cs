namespace eDocLib;

/// <summary>High-level failure category for <see cref="EdocException"/> (not a wire protocol code).</summary>
public enum EdocFailureKind
{
    /// <summary>Unclassified failure; inspect exception message or inner exception.</summary>
    Unknown = 0,

    /// <summary>File or stream I/O failure (read/write/open).</summary>
    Io = 1,

    /// <summary>Bytes do not match an expected container or XML encoding.</summary>
    InvalidFormat = 2,

    /// <summary>Recognized format but ZIP/XML layout violates structural rules.</summary>
    InvalidStructure = 3,

    /// <summary>Requested mutation or validation mode is not permitted in the current state.</summary>
    OperationNotAllowed = 4,
}
