namespace eDocLib.Asic.Container;

/// <summary>
/// Light-weight ASiC-E ZIP probe outcome (see <see cref="Edoc.TryDetectContainer"/>).
/// The interface name omits “E” because this library does not expose probes for other ASiC profiles (e.g. ASiC-S).
/// </summary>
public interface IAsicProbeResult
{
    /// <summary>Whether the ZIP shell matches an ASiC-E-style layout (mimetype + META-INF manifest within scan limits).</summary>
    bool IsLikelyAsicE { get; }

    /// <summary>Whether the first payload entry is a stored <c>mimetype</c> with expected media type.</summary>
    bool MimeTypeEntryValid { get; }

    /// <summary>Whether <c>META-INF/manifest.xml</c> appeared within the scanned prefix.</summary>
    bool ManifestEntrySeen { get; }

    /// <summary>When <see cref="IsLikelyAsicE"/> is <c>false</c>, a short machine-oriented reason.</summary>
    string? RejectionReason { get; }
}
