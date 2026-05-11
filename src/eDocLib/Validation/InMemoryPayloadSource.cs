using System.Collections.Generic;
using System.IO;

namespace eDocLib.Validation;

/// <summary>
/// Adapter that exposes an in-memory <c>byte[]</c> dictionary as an <see cref="IValidationPayloadSource"/>.
/// </summary>
/// <remarks>
/// Used by <see cref="SignatureValidator.ValidateAsync(eDocLib.Asic.Xades.XadesSignature, System.Collections.Generic.IReadOnlyDictionary{string, byte[]}, SignatureTrustPolicy?, System.Threading.CancellationToken)"/>
/// overload so existing byte-dict callers keep working while the new streaming code path takes over for
/// container validation. Each <see cref="TryOpen"/> hands back a fresh <see cref="MemoryStream"/> view over
/// the bytes; the verifier does not need to dispose it.
/// </remarks>
internal sealed class InMemoryPayloadSource : IValidationPayloadSource
{
    private readonly IReadOnlyDictionary<string, byte[]> _byUri;

    public InMemoryPayloadSource(IReadOnlyDictionary<string, byte[]> byUri)
    {
        _byUri = byUri ?? throw new ArgumentNullException(nameof(byUri));
    }

    public bool TryOpen(string relativeUri, out Stream stream)
    {
        if (_byUri.TryGetValue(relativeUri, out var bytes))
        {
            stream = new MemoryStream(bytes, writable: false);
            return true;
        }

        stream = Stream.Null;
        return false;
    }
}
