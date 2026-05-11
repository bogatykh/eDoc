namespace eDocLib.Validation;

/// <summary>
/// Built-in additions for <see cref="TslQualificationMapper"/> aligned with the Latvia national trust service list
/// as linked from the EU List of Trusted Lists (same publication endpoint as <c>TSLLocation</c> for territory LV).
/// Hosts may merge further URIs via <see cref="TslQualificationMappingOptions.Merge"/>.
/// </summary>
internal static class TslQualificationMappingDefaults
{
    /// <summary>
    /// Grants <see cref="TslQualificationIndicators.ServiceStatusIsGranted"/> for ETSI <c>accredited</c> status
    /// (used alongside <c>granted</c> / <c>recognisedatnationallevel</c> on the published Latvia XML snapshot),
    /// and recognises the pre-eIDAS qualified time-stamping service-type URIs that some national TSL entries
    /// still publish alongside the post-eIDAS <c>TSA/QTST</c> marker.
    /// </summary>
    /// <remarks>
    /// Both <see cref="TslQualificationMapper.ServiceTypeTsaTssQC"/> and
    /// <see cref="TslQualificationMapper.ServiceTypeTsaTssAdESQCandQES"/> appeared in earlier ETSI TS 119 612
    /// Annex D revisions for trusted lists that pre-date the eIDAS regulation. Treating them as qualified-TSA
    /// hints here keeps the EDOC 2.0 LV "kvalificēts laika zīmogs" gate satisfied for legacy TSL records that have
    /// not yet been republished with the modern <see cref="TslQualificationMapper.ServiceTypeTsaQTST"/> URI.
    /// </remarks>
    public static TslQualificationMappingOptions LatvianNationalPublished { get; } = new()
    {
        ExtraGrantedLikeServiceStatusUris = new[] { TslQualificationMapper.ServiceStatusAccredited },
        ExtraQualifiedTimestampServiceTypeUris = new[]
        {
            TslQualificationMapper.ServiceTypeTsaTssQC,
            TslQualificationMapper.ServiceTypeTsaTssAdESQCandQES,
        },
    };
}
