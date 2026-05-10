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
            Add(a);
            Add(b);
            return set.Count == 0 ? null : set.ToArray();

            void Add(IReadOnlyCollection<string>? c)
            {
                if (c is null)
                {
                    return;
                }

                foreach (var s in c)
                {
                    if (!string.IsNullOrWhiteSpace(s))
                    {
                        set.Add(s.Trim());
                    }
                }
            }
        }

        return new TslQualificationMappingOptions
        {
            ExtraGrantedLikeServiceStatusUris = Union(baseline?.ExtraGrantedLikeServiceStatusUris, extras?.ExtraGrantedLikeServiceStatusUris),
            ExtraQualifiedEsignServiceTypeUris = Union(baseline?.ExtraQualifiedEsignServiceTypeUris, extras?.ExtraQualifiedEsignServiceTypeUris),
            ExtraQualifiedEsealServiceTypeUris = Union(baseline?.ExtraQualifiedEsealServiceTypeUris, extras?.ExtraQualifiedEsealServiceTypeUris),
        };
    }
}
