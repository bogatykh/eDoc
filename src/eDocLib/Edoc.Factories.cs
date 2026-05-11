using System.IO;
using System.Threading;
using System.Threading.Tasks;
using eDocLib.Asic.Container;
using eDocLib.Configuration;
using eDocLib.Validation;

namespace eDocLib;

public sealed partial class Edoc
{
    /// <summary>Default format label for newly created packages (informative).</summary>
    public const string DefaultFormatVersion = "2.0";

    /// <summary>MIME type of the ASiC-E ZIP container (<c>mimetype</c> first entry).</summary>
    public const string AsicMimeType = AsicContainer.MimeType;

    /// <summary>
    /// Default maximum uncompressed payload size retained in memory when reading (32 MiB).
    /// Larger entries may spill to a temporary file; see <see cref="EdocLibConfig.PayloadMemoryThresholdBytes"/>.
    /// </summary>
    public const long DefaultPayloadMemoryThresholdBytes = AsicContainer.DefaultPayloadMemoryThresholdBytes;

    /// <summary>Creates a new empty EDOC package.</summary>
    /// <param name="formatVersion">Optional informational label; defaults to <see cref="DefaultFormatVersion"/>.</param>
    public static Edoc CreateNew(string? formatVersion = null) =>
        new(new AsicContainer(), NormalizeFormatVersionStatic(formatVersion));

    /// <summary>Opens a container using <paramref name="config"/> for payload spill / memory threshold.</summary>
    public static Edoc Open(EdocLibConfig config, Stream stream)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(stream);
        return EdocOpen.OpenMapped(stream, config);
    }

    /// <inheritdoc cref="Open(EdocLibConfig, Stream)"/>
    public static Edoc Open(EdocLibConfig config, string path)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentException.ThrowIfNullOrEmpty(path);
        return EdocOpen.OpenMapped(path, config);
    }

    /// <summary>Opens with <paramref name="config"/>, then verifies signatures asynchronously.</summary>
    public static async Task<EdocReadValidationResult> OpenAndValidateAsync(
        EdocLibConfig config,
        Stream stream,
        SignatureTrustPolicy? trustPolicy = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(stream);
        var edoc = Open(config, stream);
        var result = await EdocValidation.ValidateSignaturesAsync(edoc, trustPolicy, cancellationToken).ConfigureAwait(false);
        return result;
    }

    /// <summary>Non-throwing probe for ASiC-E shell layout (mimetype + manifest), on a seekable stream.</summary>
    public static bool TryDetectContainer(Stream stream, out IAsicProbeResult probe)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var ok = AsicContainerFormatProbe.TryDetectAsicE(stream, out AsicEProbeResult concrete);
        probe = concrete;
        return ok;
    }

    private static string NormalizeFormatVersionStatic(string? formatVersion) =>
        string.IsNullOrWhiteSpace(formatVersion) ? DefaultFormatVersion : formatVersion.Trim();
}
