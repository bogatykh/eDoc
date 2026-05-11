namespace eDocLib.Validation;

/// <summary>
/// Maps TSL service-type and status URIs to compact indicators for UI or downstream policy.
/// </summary>
internal static class TslQualificationMapper
{
    /// <summary>ETSI: qualified certificate for electronic signature.</summary>
    public const string ServiceTypeQCertESign = "http://uri.etsi.org/TrstSvc/Svctype/QESig/QCertESign";

    /// <summary>ETSI: qualified certificate for electronic seal.</summary>
    public const string ServiceTypeQCertESeal = "http://uri.etsi.org/TrstSvc/Svctype/QESeal/QCertESeal";

    /// <summary>ETSI TSL: service active at national / LOTL level.</summary>
    public const string ServiceStatusGranted = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted";

    /// <summary>ETSI TSL: recognised at national level (common for national lists).</summary>
    public const string ServiceStatusRecognisedAtNationalLevel =
        "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel";

    /// <summary>ETSI TSL: accredited (appears on several EU national lists, e.g. Latvia as published for LOTL).</summary>
    public const string ServiceStatusAccredited =
        "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accredited";

    private static readonly HashSet<string> QualifiedEsignTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        ServiceTypeQCertESign,
    };

    private static readonly HashSet<string> QualifiedEsealTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        ServiceTypeQCertESeal,
    };

    private static readonly HashSet<string> GrantedLikeStatuses = new(StringComparer.OrdinalIgnoreCase)
    {
        ServiceStatusGranted,
        ServiceStatusRecognisedAtNationalLevel,
    };

    /// <summary>
    /// Derives indicators from raw TSL fields (typically from <see cref="TrustedListQualification"/> or validation result).
    /// </summary>
    public static TslQualificationIndicators Map(
        IReadOnlyList<string>? serviceTypeIdentifiers,
        string? serviceStatusUri,
        TslQualificationMappingOptions? options = null)
    {
        var esign = new HashSet<string>(QualifiedEsignTypes, StringComparer.OrdinalIgnoreCase);
        var eseal = new HashSet<string>(QualifiedEsealTypes, StringComparer.OrdinalIgnoreCase);
        TslQualificationUriSets.AddTrimmedNonEmpty(options?.ExtraQualifiedEsignServiceTypeUris, esign);
        TslQualificationUriSets.AddTrimmedNonEmpty(options?.ExtraQualifiedEsealServiceTypeUris, eseal);

        var granted = new HashSet<string>(GrantedLikeStatuses, StringComparer.OrdinalIgnoreCase);
        TslQualificationUriSets.AddTrimmedNonEmpty(options?.ExtraGrantedLikeServiceStatusUris, granted);

        var types = serviceTypeIdentifiers ?? Array.Empty<string>();
        var suggestsSign = false;
        var suggestsSeal = false;
        foreach (var t in types)
        {
            if (!suggestsSign && esign.Contains(t))
            {
                suggestsSign = true;
            }

            if (!suggestsSeal && eseal.Contains(t))
            {
                suggestsSeal = true;
            }

            if (suggestsSign && suggestsSeal)
            {
                break;
            }
        }

        bool? statusGranted = null;
        if (!string.IsNullOrWhiteSpace(serviceStatusUri))
        {
            var trimmed = serviceStatusUri.Trim();
            statusGranted = granted.Contains(trimmed);
        }

        return new TslQualificationIndicators(suggestsSign, suggestsSeal, statusGranted);
    }
}
