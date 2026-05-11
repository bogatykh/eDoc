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

    /// <summary>ETSI TS 119 612 Annex D: generic time-stamping service authority (non-qualified).</summary>
    public const string ServiceTypeTsa = "http://uri.etsi.org/TrstSvc/Svctype/TSA";

    /// <summary>
    /// ETSI TS 119 612 Annex D: time-stamping service authority issuing <b>qualified electronic time-stamps</b>
    /// per eIDAS Article 42 (ETSI EN 319 421 / 319 422 conformant). This is the URI marking a TSA as a
    /// qualified TSP for the trust-service type "time-stamp".
    /// </summary>
    public const string ServiceTypeTsaQTST = "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST";

    /// <summary>
    /// ETSI TS 119 612 Annex D: time-stamping service used for qualified certificates (legacy / pre-eIDAS marker).
    /// Recognised in some national TSLs alongside <see cref="ServiceTypeTsaQTST"/>.
    /// </summary>
    public const string ServiceTypeTsaTssQC = "http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-QC";

    /// <summary>
    /// ETSI TS 119 612 Annex D: time-stamping service used for AdES with QC and for QES (legacy / pre-eIDAS marker).
    /// Recognised in some national TSLs alongside <see cref="ServiceTypeTsaQTST"/>.
    /// </summary>
    public const string ServiceTypeTsaTssAdESQCandQES = "http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-AdESQCandQES";

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

    /// <summary>
    /// Built-in qualified time-stamp service-type URIs (eIDAS Art. 42 conformant). Hosts may extend via
    /// <see cref="TslQualificationMappingOptions.ExtraQualifiedTimestampServiceTypeUris"/> (e.g. national pre-eIDAS markers).
    /// </summary>
    private static readonly HashSet<string> QualifiedTimestampTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        ServiceTypeTsaQTST,
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
        var qTsa = new HashSet<string>(QualifiedTimestampTypes, StringComparer.OrdinalIgnoreCase);
        TslQualificationUriSets.AddTrimmedNonEmpty(options?.ExtraQualifiedEsignServiceTypeUris, esign);
        TslQualificationUriSets.AddTrimmedNonEmpty(options?.ExtraQualifiedEsealServiceTypeUris, eseal);
        TslQualificationUriSets.AddTrimmedNonEmpty(options?.ExtraQualifiedTimestampServiceTypeUris, qTsa);

        var granted = new HashSet<string>(GrantedLikeStatuses, StringComparer.OrdinalIgnoreCase);
        TslQualificationUriSets.AddTrimmedNonEmpty(options?.ExtraGrantedLikeServiceStatusUris, granted);

        var types = serviceTypeIdentifiers ?? Array.Empty<string>();
        var suggestsSign = false;
        var suggestsSeal = false;
        var suggestsQTsa = false;
        foreach (var raw in types)
        {
            if (string.IsNullOrWhiteSpace(raw))
            {
                continue;
            }

            var t = raw.Trim();
            if (!suggestsSign && esign.Contains(t))
            {
                suggestsSign = true;
            }

            if (!suggestsSeal && eseal.Contains(t))
            {
                suggestsSeal = true;
            }

            if (!suggestsQTsa && qTsa.Contains(t))
            {
                suggestsQTsa = true;
            }

            if (suggestsSign && suggestsSeal && suggestsQTsa)
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

        return new TslQualificationIndicators(suggestsSign, suggestsSeal, suggestsQTsa, statusGranted);
    }
}
