namespace eDocLib.Validation;

/// <summary>
/// Built-in additions for <see cref="TslQualificationMapper"/> aligned with the Latvia national trust service list
/// as linked from the EU List of Trusted Lists (same publication endpoint as <c>TSLLocation</c> for territory LV).
/// Hosts may merge further URIs via <see cref="TslQualificationMappingOptions.Merge"/>.
/// </summary>
internal static class TslQualificationMappingDefaults
{
    /// <summary>
    /// Grants <see cref="TslQualificationIndicators.ServiceStatusIsGranted"/> for ETSI <c>accredited</c> status,
    /// used alongside <c>granted</c> / <c>recognisedatnationallevel</c> on the published Latvia XML snapshot.
    /// </summary>
    public static TslQualificationMappingOptions LatvianNationalPublished { get; } = new()
    {
        ExtraGrantedLikeServiceStatusUris = new[] { TslQualificationMapper.ServiceStatusAccredited },
    };
}
