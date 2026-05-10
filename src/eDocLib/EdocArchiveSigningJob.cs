using eDocLib.Asic.Container;
using eDocLib.Timestamp;
using eDocLib.Asic.Xades;

namespace eDocLib;

/// <summary>
/// EP-14 / XAdES-LTA archive step: requests RFC 3161 tokens and appends <c>xades:ArchiveTimeStamp</c> to an existing signature on an <see cref="Edoc"/>.
/// Pair with <see cref="Validation.SignatureTrustPolicy.ValidateArchiveTimeStampCms"/> (and optional chain) when validating;
/// message-imprint checks use <see cref="Validation.SignatureTrustPolicy.ArchiveTimestampImprintPolicy"/> (default requires a matching digest when archive tokens are present).
/// </summary>
public sealed class EdocArchiveSigningJob
{
    /// <summary>Stores the edoc.</summary>
    private readonly Edoc _edoc;

    /// <summary>Initializes a new eDoc archive signing job instance.</summary>
    public EdocArchiveSigningJob(Edoc edoc)
    {
        _edoc = edoc ?? throw new ArgumentNullException(nameof(edoc));
    }

    /// <summary>
    /// Obtains a time-stamp token from <paramref name="timestampProvider"/> and appends it under <c>xades:ArchiveTimeStamp</c>.
    /// When <paramref name="messageImprintSha256"/> is <c>null</c>, uses this library’s default digest input for archive time-stamp imprints (SHA-256).
    /// </summary>
    /// <param name="signatureIndex">Zero-based index into <see cref="IContainer.Signatures"/> (same order as iteration).</param>
    /// <param name="timestampProvider">RFC 3161 provider used to obtain the archive time-stamp token DER.</param>
    /// <param name="messageImprintSha256">Optional 32-byte SHA-256 imprint; overrides default digest policy.</param>
    /// <param name="archiveTimeStampId">Optional XML <c>Id</c>; default <c>ArchiveTimeStamp-{N}</c> based on existing archive tokens.</param>
    /// <param name="cancellationToken">Cancellation token forwarded to the timestamp provider.</param>
    public async Task AppendArchiveTimeStampAsync(
        int signatureIndex,
        ITimestampProvider timestampProvider,
        byte[]? messageImprintSha256 = null,
        string? archiveTimeStampId = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(timestampProvider);
        if (signatureIndex < 0 || signatureIndex >= _edoc.Signatures.Count)
        {
            throw new ArgumentOutOfRangeException(nameof(signatureIndex));
        }

        if (_edoc.GetSignatureAt(signatureIndex) is not AsicSignature asic)
        {
            throw new InvalidOperationException(
                "The signature at the given index is not an ASiC/XAdES detached signature (AsicSignature).");
        }

        byte[] imprint;
        if (messageImprintSha256 is null)
        {
            imprint = XadesBesSigner.ComputeDefaultArchiveTimestampImprintSha256(asic);
        }
        else
        {
            if (messageImprintSha256.Length != 32)
            {
                throw new ArgumentException("SHA-256 imprint must be exactly 32 bytes.", nameof(messageImprintSha256));
            }

            imprint = messageImprintSha256;
        }

        var id = archiveTimeStampId ?? NextArchiveTimeStampId(asic);
        var tokenDer = await timestampProvider.GetTimestampAsync(imprint, cancellationToken).ConfigureAwait(false);
        XadesBesSigner.AppendArchiveTimeStamp(asic, tokenDer, id);
    }

    /// <summary>Returns the next archive time stamp ID.</summary>
    private static string NextArchiveTimeStampId(AsicSignature signed)
    {
        var n = signed.UnsignedEncapsulatedArchiveTimeStampDer.Count + 1;
        return $"ArchiveTimeStamp-{n}";
    }
}
