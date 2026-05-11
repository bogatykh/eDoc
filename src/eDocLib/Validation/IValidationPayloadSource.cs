using System.IO;

namespace eDocLib.Validation;

/// <summary>
/// Abstraction over the payload bytes referenced by an XML-DSig <c>ds:Reference</c> in a detached signature.
/// </summary>
/// <remarks>
/// <para>
/// The verifier (<see cref="DetachedSignatureVerifier"/>) calls <see cref="TryOpen"/> per reference URI and
/// hashes the resulting stream incrementally when the reference has no XML transforms. References with a
/// non-empty <c>ds:Transforms</c> chain still require buffering (the transform API consumes an in-memory
/// representation), but this abstraction lets the buffering happen only once and only when needed.
/// </para>
/// <para>
/// Implementations must return a stream positioned at <c>0</c>. Stream ownership stays with the payload source —
/// the verifier does not dispose the returned stream. The same URI may be opened multiple times across multiple
/// signatures in the same container; implementations that wrap a shared seekable stream must rewind on each open.
/// </para>
/// </remarks>
internal interface IValidationPayloadSource
{
    /// <summary>
    /// Returns the payload stream for <paramref name="relativeUri"/>, or <c>false</c> when the URI is unknown.
    /// </summary>
    bool TryOpen(string relativeUri, out Stream stream);
}
