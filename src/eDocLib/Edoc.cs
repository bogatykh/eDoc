using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using eDocLib.Asic.Container;
using eDocLib.Configuration;
using eDocLib.Validation;
using eDocLib.Asic.Xades;

namespace eDocLib;

/// <summary>
/// EDOC (ASiC-E) container: payload files and detached XAdES signatures, with optional high-level helpers
/// (<see cref="DataObjectCount"/>, <see cref="GetSignature(int)"/>, <see cref="FormatVersion"/>).
/// Use <see cref="CreateNew"/> for an empty package and <see cref="Open(EdocLibConfig, Stream)"/> to load with mapped errors.
/// </summary>
public sealed partial class Edoc : IContainer, IValidatableDocument, IDisposable
{
    private readonly AsicContainer _container;
    private bool _disposed;
    private string _formatVersion;

    private Edoc(AsicContainer container, string formatVersion)
    {
        _container = container;
        _formatVersion = formatVersion;
    }

    /// <summary>Loads from a seekable ZIP stream (throws <see cref="AsicException"/> / ZIP/XML errors; prefer <see cref="Open(EdocLibConfig, Stream)"/> for <see cref="EdocException"/> mapping).</summary>
    internal Edoc(Stream stream, string? formatVersion = null, EdocLibConfig? config = null)
        : this(
            new AsicContainer(stream, ResolvePayloadMemoryThreshold(config), ResolvePayloadSpillTempDirectory(config)),
            NormalizeFormatVersion(formatVersion))
    {
    }

    private static long ResolvePayloadMemoryThreshold(EdocLibConfig? config)
    {
        if (config?.PayloadMemoryThresholdBytes is not { } t)
        {
            return AsicContainer.DefaultPayloadMemoryThresholdBytes;
        }

        if (t < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(config),
                $"{nameof(EdocLibConfig.PayloadMemoryThresholdBytes)} cannot be negative.");
        }

        return t;
    }

    private static string? ResolvePayloadSpillTempDirectory(EdocLibConfig? config) =>
        PayloadSpillPathNormalize.FromOptionalDirectory(config?.PayloadSpillTempDirectory);

    private static string NormalizeFormatVersion(string? formatVersion) =>
        string.IsNullOrWhiteSpace(formatVersion) ? DefaultFormatVersion : formatVersion.Trim();

    /// <inheritdoc />
    public IReadOnlyCollection<IDataFile> DataFiles
    {
        get
        {
            ThrowIfDisposed();
            return _container.DataFiles;
        }
    }

    /// <inheritdoc />
    public IReadOnlyCollection<ISignature> Signatures
    {
        get
        {
            ThrowIfDisposed();
            return _container.Signatures;
        }
    }

    /// <inheritdoc />
    public IDataFile AddDataFile(Stream stream, string name, string mimeType)
    {
        ThrowIfDisposed();
        return _container.AddDataFile(stream, name, mimeType);
    }

    /// <inheritdoc />
    public void AddSignature(ISignature signature)
    {
        ThrowIfDisposed();
        _container.AddSignature(signature);
    }

    /// <inheritdoc />
    public bool TryResolveSignature(string signatureId, [NotNullWhen(true)] out ISignature? signature)
    {
        ThrowIfDisposed();
        return _container.TryResolveSignature(signatureId, out signature);
    }

    /// <summary>Declared bundle format version string (informative; serialization remains ASiC-E).</summary>
    public string FormatVersion
    {
        get
        {
            ThrowIfDisposed();
            return _formatVersion;
        }

        set
        {
            ThrowIfDisposed();
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new ArgumentException("Format version must not be empty.", nameof(value));
            }

            _formatVersion = value.Trim();
        }
    }

    /// <summary>Number of payload files in the container (same as <see cref="IContainer.DataFiles"/> count).</summary>
    public int DataObjectCount
    {
        get
        {
            ThrowIfDisposed();
            return DataFiles.Count;
        }
    }

    /// <summary>Number of detached signatures (same as <see cref="IContainer.Signatures"/> count).</summary>
    public int SignatureCount
    {
        get
        {
            ThrowIfDisposed();
            return Signatures.Count;
        }
    }

    /// <summary>Returns the payload file at <paramref name="index"/> (same ordering as <see cref="IContainer.DataFiles"/>).</summary>
    public IDataFile GetDataObject(int index) => GetDataFileAt(index);

    /// <summary>Payload file by index (same order as iteration in <see cref="DataFiles"/>).</summary>
    public IDataFile GetDataFileAt(int index)
    {
        ThrowIfDisposed();
        return _container.GetDataFileAt(index);
    }

    /// <summary>Detached signature by index (same order as iteration in <see cref="Signatures"/>).</summary>
    public ISignature GetSignatureAt(int index)
    {
        ThrowIfDisposed();
        return _container.GetSignatureAt(index);
    }

    /// <summary>Removes a signature file by index.</summary>
    public void RemoveSignatureAt(int index)
    {
        ThrowIfDisposed();
        _container.RemoveSignatureAt(index);
    }

    /// <summary>Removes the first signature whose <see cref="ISignature.Id"/> matches <paramref name="signatureId"/>.</summary>
    /// <returns><c>true</c> if a signature was removed.</returns>
    public bool RemoveSignature(string signatureId)
    {
        ThrowIfDisposed();
        return _container.RemoveSignature(signatureId);
    }

    /// <summary>Returns diagnostic-friendly signature metadata at <paramref name="index"/>.</summary>
    public EdocSignatureInfo GetSignature(int index)
    {
        ThrowIfDisposed();
        return EdocSignatureInfo.From(_container.GetSignatureAt(index));
    }

    /// <summary>
    /// Resolves a signature by <c>ds:Signature/@Id</c> and wraps it as <see cref="EdocSignatureInfo"/> when it is <see cref="XadesSignature"/>.
    /// For the raw <see cref="ISignature"/> entry, use <see cref="IContainer.TryResolveSignature"/>.
    /// </summary>
    public bool TryGetSignature(string signatureId, [NotNullWhen(true)] out EdocSignatureInfo? info)
    {
        ThrowIfDisposed();
        info = null;
        if (!_container.TryResolveSignature(signatureId, out var sig) || sig is not XadesSignature xs)
        {
            return false;
        }

        info = new EdocSignatureInfo(xs);
        return true;
    }

    /// <summary>Adds a payload stream under <paramref name="name"/> with <paramref name="mimeType"/>.</summary>
    public IDataFile AddDataObject(Stream stream, string name, string mimeType) => AddDataFile(stream, name, mimeType);

    /// <summary>Removes the payload file at <paramref name="index"/>.</summary>
    public void RemoveDataObjectAt(int index) => RemoveDataFileAt(index);

    /// <summary>Removes a payload file by index.</summary>
    public void RemoveDataFileAt(int index)
    {
        ThrowIfDisposed();
        _container.RemoveDataFileAt(index);
    }

    /// <summary>
    /// Resets payload stream positions to zero when <see cref="Stream.CanSeek"/> allows it.
    /// Call before a second digest pass if streams were fully read during an earlier signing step.
    /// </summary>
    public void ResetPayloadStreamsIfSeekable()
    {
        ThrowIfDisposed();
        _container.ResetSeekablePayloadPositions();
    }

    /// <summary>Validates the container asynchronously (includes application-controlled online revocation when configured).</summary>
    /// <inheritdoc />
    public Task<EdocReadValidationResult> ValidateAsync(
        SignatureTrustPolicy? trustPolicy = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        return EdocValidation.ValidateSignaturesAsync(this, trustPolicy, cancellationToken);
    }

    /// <summary>Saves the container.</summary>
    public void Save(Stream stream)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(stream);
        _container.Save(stream);
    }

    /// <summary>
    /// Optionally runs <see cref="ValidateAsync"/> before writing. When <paramref name="validateSignaturesFirst"/> is <c>true</c>,
    /// requires every signature to pass when at least one signature exists.
    /// </summary>
    /// <exception cref="InvalidOperationException">Validation ran and one or more signatures failed.</exception>
    public async Task SaveAsync(
        Stream stream,
        bool validateSignaturesFirst,
        SignatureTrustPolicy? trustPolicyForValidation = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(stream);
        if (validateSignaturesFirst)
        {
            var r = await ValidateAsync(trustPolicyForValidation, cancellationToken).ConfigureAwait(false);
            if (r.HasSignatures && !r.AllSignaturesValid)
            {
                throw new InvalidOperationException(
                    "Container save was blocked because signature validation failed; see EdocReadValidationResult from ValidateAsync().");
            }
        }

        _container.Save(stream);
    }

    /// <summary>
    /// Releases payload streams opened from the ASiC ZIP (including spill-to-disk <see cref="FileStream"/>).
    /// Caller-supplied streams passed to <see cref="AddDataObject"/> are not disposed.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _container.DisposePayloadStreams();
        _disposed = true;
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(Edoc));
        }
    }
}
