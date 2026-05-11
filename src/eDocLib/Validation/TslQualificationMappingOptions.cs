namespace eDocLib.Validation;

/// <summary>Optional national / product extensions merged into trusted-list qualification mapping (EP-40 / V-05).</summary>
public sealed class TslQualificationMappingOptions
{
    /// <summary>Additional TSL <c>ServiceStatus</c> URIs merged with <see cref="TslQualificationMapper"/>’s built-in granted-equivalent statuses when deriving <see cref="TslQualificationIndicators.ServiceStatusIsGranted"/>.</summary>
    public IReadOnlyCollection<string>? ExtraGrantedLikeServiceStatusUris { get; init; }

    /// <summary>Additional <c>ServiceTypeIdentifier</c> URIs counted as qualified e-signature hints.</summary>
    public IReadOnlyCollection<string>? ExtraQualifiedEsignServiceTypeUris { get; init; }

    /// <summary>Additional <c>ServiceTypeIdentifier</c> URIs counted as qualified e-seal hints.</summary>
    public IReadOnlyCollection<string>? ExtraQualifiedEsealServiceTypeUris { get; init; }

    /// <summary>
    /// Additional <c>ServiceTypeIdentifier</c> URIs counted as qualified time-stamp service (TSA) hints.
    /// The mapper recognises ETSI <c>TSA/QTST</c> by default; use this to add legacy or national URIs
    /// (for example <see cref="TslQualificationMapper.ServiceTypeTsaTssQC"/> /
    /// <see cref="TslQualificationMapper.ServiceTypeTsaTssAdESQCandQES"/> for pre-eIDAS records).
    /// </summary>
    public IReadOnlyCollection<string>? ExtraQualifiedTimestampServiceTypeUris { get; init; }

    /// <summary>
    /// Union of URI collections (case-insensitive); when both inputs are empty, returns <c>null</c>.
    /// </summary>
    public static TslQualificationMappingOptions? Merge(TslQualificationMappingOptions? baseline, TslQualificationMappingOptions? extras)
    {
        if (baseline is null && extras is null)
        {
            return null;
        }

        static string[]? Union(IReadOnlyCollection<string>? a, IReadOnlyCollection<string>? b)
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            TslQualificationUriSets.AddTrimmedNonEmpty(a, set);
            TslQualificationUriSets.AddTrimmedNonEmpty(b, set);
            return set.Count == 0 ? null : set.ToArray();
        }

        return new TslQualificationMappingOptions
        {
            ExtraGrantedLikeServiceStatusUris = Union(baseline?.ExtraGrantedLikeServiceStatusUris, extras?.ExtraGrantedLikeServiceStatusUris),
            ExtraQualifiedEsignServiceTypeUris = Union(baseline?.ExtraQualifiedEsignServiceTypeUris, extras?.ExtraQualifiedEsignServiceTypeUris),
            ExtraQualifiedEsealServiceTypeUris = Union(baseline?.ExtraQualifiedEsealServiceTypeUris, extras?.ExtraQualifiedEsealServiceTypeUris),
            ExtraQualifiedTimestampServiceTypeUris = Union(baseline?.ExtraQualifiedTimestampServiceTypeUris, extras?.ExtraQualifiedTimestampServiceTypeUris),
        };
    }
}
